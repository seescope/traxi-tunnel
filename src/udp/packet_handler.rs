use super::super::{Result, TraxiError, PacketError};
use tunnel::{Environment, UDPSessionMap, TraxiTunnel, TraxiMessage};
use super::session::UDPSession;
use packet_helper::build_udp_packet;
use std::time::Duration;
use std::net::{SocketAddr, IpAddr};
use mio::{Token, EventLoop, EventSet, PollOpt};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

pub fn handle_write_udp<T: Environment>(
    data: Vec<u8>,
    mut sessions: &mut UDPSessionMap,
    mut event_loop: &mut EventLoop<TraxiTunnel<T>>,
    token: Token,) -> Result<Vec<u8>> 
{
    // Fetch session from map.
    let session = try!(sessions.get_mut(&token).ok_or(
            TraxiError::PacketError(PacketError::DropPacket(format!("Attempted to write to finished session {:?}.", token.as_usize())))
    ));

    // Reset UDP Session timeout.
    if let Some(ref timeout) = session.timeout {
        event_loop.clear_timeout(&timeout);
    }

    // Set timeout for 30 seconds.
    let udp_timeout = Duration::from_millis(30000);
    session.timeout = event_loop.timeout(TraxiMessage::CloseUDPSession(token.clone()), udp_timeout).ok();

    // Build a UDP packet to be sent back to the tunnel.
    Ok(build_udp_packet(data, &session))
}

pub fn handle_read_udp<T: Environment>(
    packet: &[u8],
    data: Vec<u8>,
    environment: &mut T,
    token: Token,
    mut event_loop: &mut EventLoop<TraxiTunnel<T>>,
    mut sessions: &mut UDPSessionMap) -> Result<Token> 
{
    if sessions.get(&token).is_none() {
        let session:UDPSession = try!(UDPSession::new(packet, environment, token.clone()));
        try!(event_loop.register(&session.socket, token.clone(), EventSet::all(), PollOpt::edge() | PollOpt::oneshot()));
        debug!("[READ_UDP]: Created new UDP session: {:?}", session);
        sessions.insert(token, session);
    } 

    // Unwrap is fine here, as we've inserted above.
    let session = sessions.get_mut(&token).unwrap();

    // Reset UDP Session timeout.
    if let Some(ref timeout) = session.timeout {
        event_loop.clear_timeout(&timeout);
    }

    // Push packet to write queue to be sent to remote.
    let target_address = get_target_address(&packet[..]);
    session.write_queue.push_back((target_address, data));

    // Set timeout for 30 seconds.
    let udp_timeout = Duration::from_millis(30000);
    session.timeout = event_loop.timeout(TraxiMessage::CloseUDPSession(token.clone()), udp_timeout).ok();

    // Re-register the event loop.
    try!(event_loop.reregister(&session.socket, token.clone(), EventSet::all(), PollOpt::edge() | PollOpt::oneshot()));

    Ok(token)
}

fn get_target_address(packet: &[u8]) -> SocketAddr {
    let ip_header = Ipv4Packet::new(packet).unwrap();
    let udp_header = UdpPacket::new(&ip_header.payload()[..]).unwrap();

    let destination_ip = ip_header.get_destination();
    let destination_port = udp_header.get_destination();

    SocketAddr::new(IpAddr::V4(destination_ip), destination_port)
}
