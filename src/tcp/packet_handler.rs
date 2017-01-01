use super::super::{Result, PacketError, TraxiError};
use super::super::packet_helper::*;
use super::super::tunnel::{TraxiTunnel, Environment, SessionMap, TraxiMessage};
use std::thread::sleep;
use std::time::Duration;
use std::result;
use std::net;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use super::session::{TCPSession, TCPState, get_socket_uid};
use mio::{PollOpt, EventLoop, EventSet, Token, Handler};
use mio::tcp::TcpStream;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use regex::Regex;

#[cfg(target_os="android")]
const SHOULD_CHECK_UID:bool = true;

#[cfg(not(target_os="android"))]
const SHOULD_CHECK_UID:bool = false;

pub fn handle_read_tcp<T: Environment>(
    packet: &[u8],
    packet_type: TCP,
    mut event_loop: &mut EventLoop<TraxiTunnel<T>>,
    mut sessions: &mut SessionMap,
    mut environment: &mut T,
    token: Token,
    ) -> Result<Token> {
    let ip_header = try!(Ipv4Packet::new(&packet[..20])
                          .ok_or(PacketError::RejectPacket(format!("Invalid packet: {:?}", &packet[20..]))));
    let tcp_header = try!(TcpPacket::new(&packet[20..])
                          .ok_or(PacketError::RejectPacket(format!("Invalid packet: {:?}", &packet[20..]))));

    // TODO: Extract to handle_rst
    // If this is an RST then just drop the session.
    if packet_type == TCP::RST {
        match sessions.remove(&token)  {
            Some(_) =>  error!("TUNNEL {}| Received RST - removed session {:?}", token.as_usize(), token.as_usize()),
            None    =>  error!("TUNNEL {}| Received RST but couldn't remove session {:?}.", token.as_usize(), token)
        }

        return Ok(token)
    }

    // TODO: Extract to handle SYN.
    if packet_type == TCP::SYN {
        // If this is a SYN packet for a new session, create the session now an add it to the map.
        if sessions.get(&token).is_none() {
            let mut session = try!(TCPSession::new(packet, environment));
            debug!("TUNNEL {}| Built new session: {:?}", token.as_usize(), session);
            
            if let Some(ref socket) = session.socket {
                try!(event_loop.register(socket, token.clone(), EventSet::readable(), PollOpt::edge() | PollOpt::oneshot()));
            }

            let uuid = environment.get_uuid(&ip_header.get_source());
            session.app_logger.uuid = uuid;

            sessions.insert(token, session);
        } 

        // This is a duplicate SYN for a session that we have already started. We can safely
        // discard it.
        else {
            return Err(TraxiError::from(PacketError::DropPacket("Received duplicate SYN".to_string())));
        }
    }

    // TODO: Extract to fetch_session
    // Fetch the session from the session map. If it's not present, this is an error.
    let session = try!(sessions.get_mut(&token).ok_or({
        if packet_type == TCP::FINACK {
            PacketError::DropPacket("Received FIN/ACK without session".to_string())
        } else {
            PacketError::RejectPacket(format!("Token {} not found in session map. Dropping {:?} and sending RST.", token.as_usize(), packet_type))
        }
    }));

    // Update the window size, if neccessary.
    session.update_window_size(&tcp_header);


    // TODO: Extract
    if session.app_logger.app_id.is_none() && SHOULD_CHECK_UID { set_app_id_for_session(session, environment) }

    // TODO: Clean up into handle_closed, handle_syn_sent etc.
    // Switch on the state of the session.
    match session.state {
        // This is a new session, begin the next step of the TCP Handshake.
        TCPState::Closed        => {
            match packet_type {
                TCP::SYN => {
                    debug!("TUNNEL C {}| Received SYN. Sending SYN/ACK back to tunnel.", token.as_usize());
                    session.send_syn_ack(event_loop); // TODO: Handle error?
                    session.state = TCPState::SynSent;
                },
                _       => { 
                    error!("TUNNEL C {}| Received {:?} in Closed state.", token.as_usize(), packet_type);
                }
            }
        }

        TCPState::SynSent       => {
            session.state = TCPState::Established;
            debug!("TUNNEL S {}| READ ACK. Connection established! SEQ: {} - ACK: {}", token.as_usize(), session.sequence_number, session.acknowledgement_number);

            // Increment the sequence number.
            session.sequence_number += 1;
            debug!("TUNNEL S {}| Increment SEQ by 1 to {}", token.as_usize(), session.sequence_number);
            
            // Now that we're established, flush the read queue.
            session.flush_read_queue(&mut event_loop);
        },

        TCPState::Established   => {
            match packet_type {
                TCP::Data(payload, _) => {
                    if session.socket.is_some() {
                        try!(detect_retransmission(token.as_usize(), &tcp_header, &session));
                        handle_data(payload, session, event_loop, token, tcp_header);
                    }   else {
                        try!(handle_connect(payload, session, event_loop, token, tcp_header));
                    }
                },
                TCP::ACK(_) => {
                    handle_ack(session, event_loop, token, tcp_header);
                }
                TCP::FINACK => {
                    debug!("TUNNEL E {}| READ FIN/ACK. MOVING TO CLOSEWAIT", token.as_usize());
                    session.state = TCPState::CloseWait;

                    // Increment the acknowledgement number.
                    session.acknowledgement_number += 1;

                    let sequence_number = session.sequence_number;
                    session.send_ack(event_loop, sequence_number);
                    debug!("TUNNEL CW {}| SENT ACK SEQ: {} - ACK: {}", token.as_usize(), session.sequence_number, session.acknowledgement_number);
                    session.send_fin_ack(event_loop);
                    debug!("TUNNEL CW {}| SENT FIN SEQ: {} - ACK: {}", token.as_usize(), session.sequence_number, session.acknowledgement_number);
                }

                // Error Cases.
                TCP::SYN => {
                    error!("TUNNEL E {}| READ SYN. Should not have happened! Removing session {:?}", token.as_usize(), session);
                    session.close_session(event_loop);
                }
                TCP::SYNACK => {
                    error!("TUNNEL E {}| READ SYNACK. Should not have happened! Removing session {:?}", token.as_usize(), session);
                    session.close_session(event_loop);
                }
                TCP::RST => {
                    error!("TUNNEL E {}| READ RST. Removing session {:?}", token.as_usize(), session);
                    session.close_session(event_loop);
                }
            };

            // The read queue may need flushing.
            session.flush_read_queue(&mut event_loop);
        },
        
        // This is a session that is being closed. We wait for an ACK of our FIN.
        TCPState::FinWait1       => {
            match packet_type {
                TCP::ACK(_) | TCP::FINACK => {
                    // Check if this is a duplicate ACK, and therefore a sign of transmission loss.
                    let packet_acknowledgement = tcp_header.get_acknowledgement();

                    session.check_duplicate_ack(packet_acknowledgement);

                    // If this is a non-duplicate ACK, move to FinWait2.
                    if session.duplicate_ack_count == 0 {
                        debug!("TUNNEL F1 {}| READ ACK. MOVING TO FINWAIT2. SEQ: {} - ACK: {}",
                               token.as_usize(), session.sequence_number, session.acknowledgement_number);
                        session.state = TCPState::FinWait2;
                    }

                    // If we've now entered Fast Retransmit, retransmit the last packet in the queue on ever 3rd duplicate ACK.
                    if session.entered_fast_retransmit.is_some() && session.duplicate_ack_count % 3 == 0 {
                        session.retransmit_last_packet(&mut event_loop);
                    }
                } 

                TCP::Data(payload, _) => handle_data(payload, session, event_loop, token, tcp_header),

                ref invalid_type => {
                    error!("TUNNEL F1 {}| READ {:?}. Should not have happened. Removing session.", token.as_usize(), invalid_type);
                    session.close_session(event_loop);
                }
            };

            // The read queue may need flushing.
            session.flush_read_queue(&mut event_loop);
        },

        // We've received the FINACK from the client, send an ACK. The sending process will
        // handle closing the connection.
        TCPState::FinWait2       => {
            match packet_type {
                TCP::FINACK => {
                    session.state = TCPState::TimeWait;
                    let sequence_number = session.sequence_number;
                    session.acknowledgement_number += 1;
                    session.send_ack(event_loop, sequence_number + 1);
                    debug!("TUNNEL F2 {}| READ FIN. SENT ACK, MOVING TO TIMEWAIT. SEQ: {} - ACK: {}",
                           token.as_usize(), session.sequence_number, session.acknowledgement_number);
                }             
                TCP::Data(payload, _) => {
                    try!(detect_retransmission(token.as_usize(), &tcp_header, &session));
                    handle_data(payload, session, event_loop, token, tcp_header);
                }
                _ => {
                    error!("TUNNEL F2 {}| READ {:?}. Should not have happened. Ignoring packet.", token.as_usize(), packet_type);
                }
            }
        }

        TCPState::CloseWait     => {
            error!("TUNNEL CW {}| READ {:?}. Should not have happened. Doing nothing.", token.as_usize(), packet_type);
        }

        TCPState::TimeWait      => {
            error!("TUNNEL TW {}| READ {:?}. Should not have happened. Doing nothing.", token.as_usize(), packet_type);
        }

        TCPState::LastAck       => {
            match packet_type {
                TCP::ACK(_) => {
                    let acknowledgement_number = tcp_header.get_acknowledgement();
                    let expected_acknowledgement = session.sequence_number + 1;
                    if acknowledgement_number == expected_acknowledgement {
                        debug!("TUNNEL LA {}| READ ACK. CLOSING SESSION. SEQ: {} - ACK: {} - PACKET ACK: {}",
                               token.as_usize(), session.sequence_number, session.acknowledgement_number, acknowledgement_number);
                        // Close the session.
                        session.close_session(event_loop);
                    } else {
                        debug!("TUNNEL LA {}| ACKNOWLEDGEMENT DOES NOT MATCH. EXPECTED: {}, GOT {}",
                               token.as_usize(), expected_acknowledgement, acknowledgement_number);
                    }
                }
                _  => {
                    error!("TUNNEL LA {}| READ {:?}. Should not have happened. Doing nothing.", token.as_usize(), packet_type);
                }
            }
            
        }
    }; 

    session.reregister(event_loop).map(|_| token).map_err(|e| TraxiError::from(e))
}

pub fn handle_write_tcp(
    packet: TCP,
    mut sessions: &mut SessionMap,
    token: Token
    ) -> Result<Vec<u8>> {

    let new_packet;

    {
        // Get session from map.
        let session_option = sessions.get_mut(&token);

        // If there's no matching session, reject the packet.
        if session_option.is_none() {
            return Err(TraxiError::from(PacketError::RejectPacket(format!("TUNNEL WRITE| Attempted to write to finished session {:?}.", token))));
        } 

        let session = session_option.unwrap();

        // If we are in CloseWait and we have sent a FIN, transition to LastAck.
        if session.state == TCPState::CloseWait && packet == TCP::FINACK {
            session.state = TCPState::LastAck;
            debug!("HANDLE_WRITE_TCP CW {}| Sending FINACK. Moving to LastAck", token.as_usize());
        }

        new_packet = match packet {
            TCP::ACK(sequence_number)           => {
                debug!("HANDLE_WRITE_TCP ACK {}| Writing {}", token.as_usize(), sequence_number);
                build_ack(session, sequence_number)
            }
            TCP::RST                            => build_rst(session),
            TCP::SYNACK                         => build_syn_ack(session),
            TCP::FINACK                         => build_fin_ack(session),
            TCP::Data(data, sequence_number)    => {
                debug!("HANDLE_WRITE_TCP DATA {}| Writing {}", token.as_usize(), sequence_number);
                build_data_packet(session, &data[..], sequence_number)
            }
            TCP::SYN         => {
                let reason = format!("TOKEN {} ATTEMPTED TO ADD SYN TO WRITE QUEUE. THIS SHOULD NOT HAPPEN.", token.as_usize());
                return Err(TraxiError::from(PacketError::RejectPacket(reason)));
            }
        };
    }

    Ok(new_packet)
}

fn set_app_id_for_session<E: Environment>(session: &mut TCPSession, environment: &mut E) {
    let mut retries = 0;
    if session.app_logger.app_id == None {
        sleep(Duration::from_millis(1));
        session.app_logger.app_id = get_socket_uid(session.source_ip, session.source_port)
            .map(|u| environment.get_package_name(u));
    }

    while session.app_logger.app_id == None && retries <= 3 {
        sleep(Duration::from_millis(10));
        session.app_logger.app_id = get_socket_uid(session.source_ip, session.source_port)
            .map(|u| environment.get_package_name(u));

        retries += 1;
    }
}

fn handle_connect<H: Handler<Message=TraxiMessage, Timeout=TraxiMessage>>(
    payload: Vec<u8>,
    mut session: &mut TCPSession,
    mut event_loop: &mut EventLoop<H>,
    token: Token,
    tcp_header: TcpPacket) -> result::Result<(), PacketError> {

    debug!("HANDLE_CONNECT {}| BEGIN", token.as_usize());

    // Normal TCP crap
    let payload_length = payload.len() as u32;
    session.acknowledgement_number += payload_length;

    let packet_acknowledgement = tcp_header.get_acknowledgement();
    session.update_unacknowledged(packet_acknowledgement, event_loop);

    // Get the destination out of the request.
    session.app_logger.set_domain(&payload, 80); // Use port 80 here as we're parsing TCP.

    let host_address = session.app_logger.destination.clone();

    // If the destination is still our dummy IP address, something failed.
    if host_address == "123.123.123.123" {
      return Err(PacketError::DropPacket(format!("Unable to parse domain from request.")))
    }

    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut host = SocketAddr::new(ip, 443);
    let host_address = parse_domain(&host_address);

    if Regex::new(r"\w+").unwrap().is_match(&host_address) {
        // This is a domain. We need to resolve it.
        let mut lookup_result = try!(
            net::lookup_host(&host_address).map_err(|e| 
              PacketError::DropPacket(format!("Couldn't resolve {}: {:?}", host_address, e))
            )
        );

        let resolved_host = try!(lookup_result.next().ok_or(
            PacketError::DropPacket(format!("No host in lookup result"))
        ));

        host.set_ip(resolved_host.ip());
    } else {
        let ip = try!(IpAddr::from_str(&host_address).map_err(|e| {
            PacketError::DropPacket(format!("Couldn't parse IP address {}: {:?}", host_address, e))
        }));

        host.set_ip(ip);
    }


    debug!("HANDLE_CONNECT {}| Succesfully resolved {} to {:?}. Connecting..",
           token.as_usize(), host_address, host);

    // Connect to the socket
    let socket = try!(TcpStream::connect(&host).map_err(|e|
                          PacketError::DropPacket(format!("Couldn't connect to socket: {:?}", e))
                      ));

    debug!("HANDLE_CONNECT {}| Succesfully connected. Socket is {:?}. Registering..",
           token.as_usize(), socket);

    // Register the socket
    try!(event_loop.register(&socket, token.clone(), EventSet::readable(), PollOpt::edge() | PollOpt::oneshot()).map_err(|e|
      PacketError::DropPacket(format!("Couldn't register session: {:?}", e))
    ));

    // Set the socket.
    session.socket = Some(socket);

    // Set the App ID by parsing the User-Agent header in the CONNECT request.
    session.app_logger.set_app_id(&payload);

    // Send back "connection established"
    let payload = b"HTTP/1.1 200 Connection established\r\n\r\n";

    debug!("HANDLE_CONNECT {}| All done! Sending connection established.", token.as_usize());
    session.send_data(payload, event_loop);

    Ok(())
}

fn handle_data<H: Handler<Message=TraxiMessage, Timeout=TraxiMessage>>
    (payload: Vec<u8>, mut session: &mut TCPSession, mut event_loop: &mut EventLoop<H>, token: Token, tcp_header: TcpPacket) {
    let payload_length = payload.len() as u32;
    let sequence_number = session.sequence_number;
    debug!("TUNNEL E {} DATA| READ {}. SEQ: {} - ACK: {}.", token.as_usize(), payload_length, session.sequence_number, session.acknowledgement_number);

    let packet_sequence = tcp_header.get_sequence();
    let packet_acknowledgement = tcp_header.get_acknowledgement();

    // Update the session's UNA field.
    session.update_unacknowledged(packet_acknowledgement, event_loop);


    // Make sure this is a valid sequence.
    if session.is_valid_segment(packet_sequence) {
        // Set domain, if it's not already set.
        if session.destination_port == 80 || session.destination_port == 443 {
            session.app_logger.set_domain(&payload, session.destination_port);
            session.app_logger.set_app_id(&payload)
        }

        // Push the packet into the write queue.
        session.write_queue.push(payload);

        // Update the session's ACK
        session.acknowledgement_number += payload_length;
        debug!("TUNNEL E {} DATA| Incremented ACK by {} to {}",
               token.as_usize(), payload_length, session.acknowledgement_number);

        session.send_ack(&mut event_loop, sequence_number);
        session.interest.insert(EventSet::writable())
    } else {
        // This segment is invalid. Send a duplicate ACK.
        error!("TUNNEL E {} DATA| ERROR: Invalid segment! SEQ: {} - ACK {} - SEG.SEQ {}",
               token.as_usize(), session.sequence_number, session.acknowledgement_number, packet_sequence);
        session.send_ack(&mut event_loop, sequence_number);
    }
}

fn handle_ack<H: Handler<Message=TraxiMessage, Timeout=TraxiMessage>>(
    mut session: &mut TCPSession, mut event_loop: &mut EventLoop<H>, token: Token, tcp_header: TcpPacket) {
    let packet_acknowledgement = tcp_header.get_acknowledgement();
    debug!("TUNNEL E {} ACK| READ ACK. SEQ: {} - ACK: {} - UNA {} - SEG.ACK {}",
           token.as_usize(), session.sequence_number, session.acknowledgement_number, session.unacknowledged, packet_acknowledgement);

    // *** THE ORDER OF THESE FUNCTION CALLS IS VERY IMPORTANT **

    // 1. Update the session's UNA field.
    session.update_unacknowledged(packet_acknowledgement, event_loop);

    // 2. Check if this is a duplicate ACK, and therefore a sign of transmission loss.
    session.check_duplicate_ack(packet_acknowledgement);

    // 3. Update the retransmission queue, removing any newly acknowledged packets.
    session.update_retransmission_queue(packet_acknowledgement);

    // 4. Expand congestion window based on the above information.
    session.expand_congestion_window();

    // 5. Finally, if we're in fast_retransmit mode, and we haven't had more than 3 ACKs,
    //    retransmit the oldest packet in the queue.
    if session.entered_fast_retransmit.is_some() && session.duplicate_ack_count <= 3 {
        session.retransmit_last_packet(&mut event_loop);
    }
}

fn detect_retransmission(token: usize, tcp_header: &TcpPacket, session: &TCPSession) -> result::Result<(), PacketError> {
    // If this is a re-transmission, drop the packet.
    debug!("DETECT_RETRANSMISSION {}| PACKET SEQUENCE: {} | PACKET ACKNOWLEDGEMENT: {} | SESSION SEQUENCE: {} | SESSION
    ACKNOWLEDGEMENT {}", token, tcp_header.get_sequence(), tcp_header.get_acknowledgement(),
    session.sequence_number, session.acknowledgement_number);

    if (session.state != TCPState::Closed && session.state != TCPState::SynSent) && 
       tcp_header.get_sequence() < session.acknowledgement_number {
           let error_message = format!("{} Received retransmission", token);
           Err(PacketError::DropPacket(error_message))
    } else {
        return Ok(())
    }
}

fn parse_domain(domain: &str) -> &str {
    domain.split(":").into_iter().next().unwrap_or("")
}

#[test]
fn test_parse_domain() {
    let test_domain = "api.twitter.com:443";
    let expected_domain = "api.twitter.com";

    assert_eq!(parse_domain(test_domain), expected_domain);
}
