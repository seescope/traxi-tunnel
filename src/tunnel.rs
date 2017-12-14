use super::{Result, PacketError, TraxiError};
use libc::c_int;

use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::hash::Hasher;
use std::time::Duration;

use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use mio::{Io, Token, Handler, EventLoop, EventSet, TryRead, TryWrite, PollOpt};
use mio::unix::{UnixListener, UnixStream};

use bytes::{ByteBuf, MutByteBuf};

use fnv::FnvHasher;

use tcp::session::{TCPSession};
use udp::session::UDPSession;
use packet_helper::*;
use tcp::packet_handler::{handle_write_tcp, handle_read_tcp};
use udp::packet_handler::{handle_write_udp, handle_read_udp};
use kinesis_handler::KinesisHandler;
use log_entry::LogEntry;

pub type SessionMap = HashMap<Token, TCPSession>;
pub type UDPSessionMap = HashMap<Token, UDPSession>;
const TUNNEL:Token = Token(0);
const IPC_SERVER:Token = Token(1);
const IPC_CLIENT:Token = Token(2);

pub trait Environment {
    fn protect(&self, socket: c_int) -> bool;
    fn get_package_name(&mut self, uid: usize) -> String;
    fn report_error(&self, message: &str);
    fn get_uuid(&mut self, &Ipv4Addr) -> Option<String>;
    fn get_file_path(&self) -> String;
}

/// TraxiTunnel is our handler for the `event_loop` (see [MIO's
/// documentation](http://rustdoc.s3-website-us-east-1.amazonaws.com/mio/v0.5.x/mio/struct.EventLoop.html).
/// It primary deals with receiving and sending data to and from the device, and managing sessions.
pub struct TraxiTunnel<T> {
    pub tunnel: Io,
    pub tcp_sessions: SessionMap,
    pub udp_sessions: UDPSessionMap,
    interest: EventSet,
    environment: T,
    write_queue: Vec<(PacketType, Token)>,
    mut_buf: Option<MutByteBuf>,
    ipc_server: UnixListener,
    ipc_client: Option<UnixStream>,
    log_queue: Vec<LogEntry>,
    kinesis_handler: KinesisHandler,
}

impl<T: Environment> TraxiTunnel<T> {
    /// Create a new TraxiTunnel. The `tunnel` param wraps on a open file descriptor pointing to
    /// `tun` interface on the device, which is where we will receive data from and send data to
    /// the device.
    pub fn new(tunnel: Io, environment: T, ipc_server: UnixListener) -> TraxiTunnel<T> {
        TraxiTunnel {
            tunnel: tunnel,
            tcp_sessions: SessionMap::new(),
            udp_sessions: UDPSessionMap::new(),
            interest: EventSet::readable(),
            mut_buf: Some(ByteBuf::mut_with_capacity(4068)),
            environment: environment,
            write_queue: vec![],
            ipc_server: ipc_server,
            ipc_client: None,
            log_queue: Vec::new(),
            kinesis_handler: KinesisHandler::new(),
        }
    }

    /// The tunnel file descriptor is now ready to write data back to the device.
    pub fn writable(&mut self, mut event_loop: &mut EventLoop<TraxiTunnel<T>>) -> Result<()> {
        if self.write_queue.len() > 0 {
            let (packet, token) = self.write_queue.remove(0);
            let new_packet = match packet {
                PacketType::TCP(tcp_packet) => try!(handle_write_tcp(tcp_packet,
                                                                &mut self.tcp_sessions,
                                                                token)),
                PacketType::UDP(data)    => try!(handle_write_udp(data,
                                                                &mut self.udp_sessions,
                                                                &mut event_loop,
                                                                token))
            };
            match self.tunnel.try_write(&new_packet[..]) {
                Ok(None) => {
                    debug!("TUNNEL WRITE {}| Client flushing buf; WOULDBLOCK", token.as_usize());
                    self.interest.insert(EventSet::writable());
                }
                Ok(Some(written)) => {
                    debug!("TUNNEL WRITE| WROTE {}", written);
                    self.interest.remove(EventSet::writable());
                }
                Err(e) => debug!("not implemented; client err={:?}", e),
            }
        }

        // If there are still more writes to perform, register for writes again.
        if self.write_queue.len() > 0 {
            self.interest.insert(EventSet::writable());
        }

        Ok(())
    }

    /// The tunnel file descriptor is ready to receive data from the device.
    pub fn readable(&mut self, event_loop: &mut EventLoop<TraxiTunnel<T>>) -> Result<()> {
        // Prepare a buffer to read the data.
        let mut buf = self.mut_buf.take().unwrap_or(ByteBuf::mut_with_capacity(4068));
        buf.clear();

        // Read data from the tunnel.
        match self.tunnel.try_read_buf(&mut buf) {
            // There wasn't actually any data availble to read.
            Ok(None) => {
                error!("TUNNEL| No data actually ready.");
            }

            // There was data available to read from the tunnel.
            Ok(Some(_)) => {
                match self.process_packet(event_loop, &mut buf) {
                    Ok(token)   => debug!("TUNNEL {}| Packet for session {:?} succesfully processed.", token.as_usize(), token),
                    Err(TraxiError::PacketError(PacketError::DropPacket(reason)))    => {
                        error!("TUNNEL| Error processing packet: {}. Dropping.", reason);
                    },
                    Err(TraxiError::PacketError(PacketError::RejectPacket(reason)))    => {
                        error!("TUNNEL| Error processing packet: {:?}. Rejecting packet and sending RST.", reason);
                        let packet = buf.bytes();
                        match get_packet_type(&packet[..]) {
                            Ok(PacketType::TCP(_)) => self.send_rst(&packet[..]),
                            _                      => {}
                        }
                    },
                    Err(e) => {
                        error!("TUNNEL| Error processing packet: {:?}. Dropping.", e);
                    }
                }
            },

            // We couldn't actully read from the tunnel.
            Err(e) => {
                error!("TUNNEL| Error reading from tunnel {:?}", e);
            }
        }

        // Return the buffer back to its previous state.
        self.mut_buf = Some(buf);

        Ok(())
    }

    /// Process a packet received from the tunnel. This function acts much like a state machine -
    /// when a packet is read, we act differently based on what state the corresponding session is
    /// in.
    fn process_packet(&mut self, mut event_loop: &mut EventLoop<TraxiTunnel<T>>, buf: &mut MutByteBuf) -> Result<Token> {
        let packet = buf.bytes();

        // We are always interested in the tunnel being readable.
        self.interest = EventSet::readable();
        let token = get_socket_token(packet);

        match try!(get_packet_type(packet)) {
            PacketType::TCP(tcp_packet) => {
                handle_read_tcp(
                    packet,
                    tcp_packet,
                    &mut event_loop,
                    &mut self.tcp_sessions,
                    &mut self.environment,
                    token)
            },
            PacketType::UDP(data)       => {
                handle_read_udp(
                    packet,
                    data,
                    &mut self.environment,
                    token,
                    &mut event_loop,
                    &mut self.udp_sessions)
            }
        }
    }

    /// Send an RST packet back to the sender, effectively terminating the session,
    fn send_rst(&mut self, packet: &[u8]) {
        debug!("SEND_RST| Sending RST");
        let tcp_header = TcpPacket::new(&packet[20..]);

        if tcp_header.is_none() {
            error!("SEND RST| Unable to build TCP Header using source packet {:?}. This is most likely not a TCP packet.", &packet);
            return;
        }

        let token = get_socket_token(packet);

        // HACK: Create a temporary session so we can send an RST.
        if self.tcp_sessions.get(&token).is_none() {
            let temporary_session = TCPSession::new(packet, &self.environment);
            if temporary_session.is_err() {
                error!("SEND_RST| Unable to build temporary session {:?}", temporary_session);
                return;
            }

            let mut temporary_session = temporary_session.unwrap();

            // Set the acknowledgement_number to be the same as the packet we just received.
            let tcp_header = tcp_header.unwrap();
            let acknowledgement_number = tcp_header.get_acknowledgement();
            temporary_session.sequence_number = acknowledgement_number;

            debug!("SEND_RST {}| Created temporary session: {:?}", token.as_usize(), temporary_session);
            // Insert the token into the map.
            self.tcp_sessions.insert(token, temporary_session);
        }

        error!("SEND_RST {}| Adding RST to queue", token.as_usize());
        self.write_queue.push((PacketType::TCP(TCP::RST), token));
        self.interest.insert(EventSet::writable());
    }

    fn accept_ipc(&mut self, event_loop: &mut EventLoop<TraxiTunnel<T>>) -> Result<()> {
        match self.ipc_server.accept() {
            Ok(Some(client)) => {
                debug!("ACCEPT_IPC| Client registered: {:?}", &client);
                try!(event_loop.register(&client, IPC_CLIENT, EventSet::readable(), PollOpt::edge() | PollOpt::oneshot()));
                self.ipc_client = Some(client);
                Ok(())
            },
            Ok(None) => {
                Err(TraxiError::IPCError("accept_ipc returned no client".to_string()))
            },
            Err(e) => Err(TraxiError::from(e))
        }
    }

    fn read_ipc(&mut self, _: &mut EventLoop<TraxiTunnel<T>>) -> Result<()> {
        let mut buf = [0u8; 1];
        if let Some(ref mut client) = self.ipc_client {
            match client.try_read(&mut buf[..]) {
                Ok(Some(r)) if r > 0  => {
                    let data = buf[0];
                    debug!("READ_IPC| Recevied message from IPC. Data is {}. Doing nothing.", data);
                    Ok(())
                },
                Ok(_)  => { Err(TraxiError::IPCError("Suprious read wakeup".to_string())) },
                Err(e) => { Err(TraxiError::from(e)) }
            }
        } else {
            return Err(TraxiError::IPCError("IPC Client is None".to_string()));
        }
    }
}

/// These are the methods the `event_loop` will call on `TraxiTunnel` when data or errors are
/// available on a file descriptor that we're interested in.
impl<T: Environment> Handler for TraxiTunnel<T> {
    type Timeout = TraxiMessage;
    type Message = TraxiMessage;

    /// Data is ready on a file descriptor. `token` is used to identify which one.
    fn ready(&mut self, event_loop: &mut EventLoop<TraxiTunnel<T>>, token: Token,
             events: EventSet) {

        if events.is_readable() {
            let result = match token {
                TUNNEL      => self.readable(event_loop),
                IPC_SERVER  => self.accept_ipc(event_loop),
                IPC_CLIENT  => self.read_ipc(event_loop),
                _       => {
                    if let Some(tcp_session) = self.tcp_sessions.get_mut(&token) {
                        tcp_session.readable(event_loop).map_err(|e| TraxiError::from(e))
                    } else if let Some(udp_session) = self.udp_sessions.get_mut(&token) {
                        udp_session.readable(event_loop).map_err(|e| TraxiError::from(e))
                    } else {
                        Err(TraxiError::TunnelError(format!("No session for {} found!", token.as_usize())))
                    }
                }
            };

            if let Err(e) = result {
                error!("TUNNEL_READABLE {}| Error: {:?}", token.as_usize(), e);
            }
        }

        if events.is_writable() {
            let result = match token {
                TUNNEL  => self.writable(event_loop),
                _       => {
                    if let Some(tcp_session) = self.tcp_sessions.get_mut(&token) {
                        tcp_session.writable(event_loop).map_err(|e| TraxiError::from(e))
                    } else if let Some(udp_session) = self.udp_sessions.get_mut(&token) {
                        udp_session.writable(event_loop).map_err(|e| TraxiError::from(e))
                    } else {
                        Err(TraxiError::TunnelError(format!("No session for {} found!", token.as_usize())))
                    }
                }
            };

            if let Err(e) = result {
                error!("TUNNEL_WRITABLE {}| Error: {:?}", token.as_usize(), e);
            }
        }

        // We are always interested in the tunnel being readable.
        self.interest.insert(EventSet::readable());

        // Re-register for tunnel events.
        event_loop.reregister(&self.tunnel, TUNNEL, self.interest, PollOpt::edge() | PollOpt::oneshot()).unwrap();
    }

    /// The remote session is sending a message back to the tunnel.
    fn notify(&mut self, event_loop: &mut EventLoop<TraxiTunnel<T>>, msg: TraxiMessage) {
        match msg {
            TraxiMessage::QueuePacket(packet, token) => {
                debug!("NOTIFY {}| Queueing packet.", token.as_usize());
                self.write_queue.push((packet, token));

                // Unwrap here because this should seriously never fail. If it does, we want to
                // know about it.
                event_loop.reregister(&self.tunnel, TUNNEL, EventSet::writable(), PollOpt::edge() |
                              PollOpt::oneshot()).unwrap();
            },
            TraxiMessage::CloseTCPSession(token) => {
                match self.tcp_sessions.remove(&token) {
                    Some(session) =>    debug!("NOTIFY {}| Successfully removed TCP session.", session.token.as_usize()),
                    None        =>      error!("NOTIFY {}| Unable to remove session. It was probably removed already.", token.as_usize())
                }
            },
            TraxiMessage::CloseUDPSession(token) => {
                match self.udp_sessions.remove(&token) {
                    Some(session) =>    debug!("NOTIFY {}| Successfully removed UDP session.", session.token.as_usize()),
                    None        =>      error!("NOTIFY {}| Unable to remove session. It was probably removed already.", token.as_usize())
                }
            }
            TraxiMessage::AppendToLogQueue(log_entry) => {
                let queue_length = self.log_queue.len();
                debug!("NOTIFY| Appending log entry to queue. Current size: {}", queue_length);

                self.log_queue.push(log_entry);
            }
            ref unsupported                   => {
                error!("TIMEOUT| Received unknown message {:?}", unsupported);
            }
        }
    }

    fn timeout(&mut self, event_loop: &mut EventLoop<TraxiTunnel<T>>, msg: TraxiMessage) {
        match msg {
            // A session has timed out from inactivity.
            TraxiMessage::CloseTCPSession(token) => {
                match self.tcp_sessions.remove(&token) {
                    Some(_) =>    debug!("TIMEOUT {}| Successfully removed TCP session.", token.as_usize()),
                    None    =>    error!("TIMEOUT {}| Unable to remove session. It was probably removed already.", token.as_usize())
                }
            },
            TraxiMessage::CloseUDPSession(token) => {
                match self.udp_sessions.remove(&token) {
                    Some(_) =>    debug!("TIMEOUT {}| Successfully removed UDP session.", token.as_usize()),
                    None    =>    error!("TIMEOUT {}| Unable to remove session. It was probably removed already.", token.as_usize())
                }
            },
            TraxiMessage::RetransmitLastSegment(token) => {
                if let Some(session) = self.tcp_sessions.get_mut(&token) {
                    debug!("TIMEOUT {}| Retransmitting last packet and incrementing timer.", token.as_usize());
                    session.retransmit_last_packet(event_loop);
                    session.retransmission_timer.increment_timer(event_loop, token);
                }
            }
            TraxiMessage::FlushLogQueue => {
                // Before we do *anything*, set the timer again.
                let flush_log_timeout = Duration::from_millis(1000); // 1 second
                drop(event_loop.timeout(TraxiMessage::FlushLogQueue, flush_log_timeout)); // Drop, since timeout should never fail.

                debug!("FLUSH_LOG_QUEUE| Sending events to Kinesis. Log Queue: {:?}", self.log_queue);
                self.kinesis_handler.send_events(self.log_queue.clone());

                self.log_queue = Vec::new();
            }
            TraxiMessage::DumpSessionMap => {
                // Before we do *anything*, set the timer again.
                let timeout = Duration::from_secs(300); // 5 Minutes
                drop(event_loop.timeout(TraxiMessage::DumpSessionMap, timeout)); // Drop, since timeout should never fail.

                info!("SESSION_DUMP| TOTAL_SESSIONS: {}", self.tcp_sessions.len());

                for session in self.tcp_sessions.values() {
                    info!(
                        "SESSION_DUMP| {:?}: CREATED_AT: {} | LAST_ACTIVE: {} | SOURCE: {} | DESINATION: {}",
                        session.token, session.created_at, session.last_active, session.source_ip, session.destination_ip
                    );
                }
            }
            ref unsupported                   => {
                error!("TIMEOUT| Received unknown message {:?}", unsupported);
            }
        }
    }
}

/// In order to pass data between the remote and device ends of the tunnel, the session
/// needs a way to communicate with the tunnel. It does this through the form of `Messages`.
/// `Messages` work by placing data on the event queue, calling `TraxiTunnel`'s `#notify` method
/// when it's ready. This is the enum used for that communication.
#[derive(Debug, PartialEq, Clone)]
pub enum TraxiMessage {
    /// The remote `Session` has a packet ready to be sent back to the tunnel.
    QueuePacket(PacketType, Token),

    /// The `TCPSession` has decided that the session should be closed, probably because the
    /// connection with the remote server has been closed.
    CloseTCPSession(Token),

    /// The `UDPSession` has decided that the session should be closed, probably because the
    /// connection with the remote server has been closed.
    CloseUDPSession(Token),

    /// This TCP segment has not been ACKed after a certain period of time and needs to be
    /// retransmitted.
    RetransmitLastSegment(Token),

    /// Append a byte-encoded, tab separated log string to the LogQueue.
    AppendToLogQueue(LogEntry),

    /// Write the SessionMap to disk.
    DumpSessionMap,

    /// Flush the LogQueue.
    FlushLogQueue,
}

/// Generate a unique token to identify this session.
pub fn get_socket_token(packet: &[u8]) -> Token {
    let ip_header = Ipv4Packet::new(&packet[..]).unwrap();
    let destination_ip = ip_header.get_destination();
    let source_ip = ip_header.get_source();

    let (source_port, destination_port, protocol) = match ip_header.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp     => {
            let header = TcpPacket::new(&ip_header.payload()[..]).unwrap();
            (header.get_source(), header.get_destination(), 6)
        },
        IpNextHeaderProtocols::Udp      => {
            let header = UdpPacket::new(&ip_header.payload()[..]).unwrap();
            (header.get_source(), header.get_destination(), 17)
        },
        _                               => {
            (1, 2, 3) // TODO: Fix
        }
    };


    let mut hasher = FnvHasher::default();

    for byte in destination_ip.octets().iter() {
        hasher.write_u8(*byte);
    }

    for byte in source_ip.octets().iter() {
        hasher.write_u8(*byte);
    }

    hasher.write_u16(destination_port);
    hasher.write_u16(source_port);
    hasher.write_u16(protocol);

    Token(hasher.finish() as usize)
}


#[cfg(test)]
mod test {
    extern crate test;

    use super::*;
    use mio::Token;
    use self::test::Bencher;

    #[test]
    fn test_get_socket_token_tcp() {
        let test_packet = vec![0x45, 0x00,
            0x00, 0x3c, 0x22, 0x58, 0x40, 0x00, 0x40, 0x06, 0x93, 0xeb, 0xc0, 0xa8, 0x01, 0xb8, 0xc0, 0xa8,
            0x01, 0x70, 0xa1, 0x7f, 0x00, 0x17, 0x33, 0xea, 0x37, 0xf6, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0x39, 0x08, 0x84, 0xa7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x0f,
            0x15, 0xae, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06
        ];
        let expected_socket_token = Token(1219997511629748572);

        let socket_token = get_socket_token(&test_packet[..]);
        assert_eq!(socket_token, expected_socket_token);
    }

    #[test]
    fn test_get_socket_token_udp() {
        let test_packet = vec![
        0x45, 0x00, 0x00, 0x23, 0xdd, 0xb1, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xf5, 0xe2, 0x04, 0xd2, 0x00, 0x0f, 0xfe, 0x22,
        0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x0a];

        let expected_socket_token = Token(14026642593478978491);

        let socket_token = get_socket_token(&test_packet[..]);
        assert_eq!(socket_token, expected_socket_token);
    }

    #[bench]
    fn test_get_socket_token(b: &mut Bencher) {
        let test_packet = vec![0x45, 0x00,
            0x00, 0x3c, 0x22, 0x58, 0x40, 0x00, 0x40, 0x06, 0x93, 0xeb, 0xc0, 0xa8, 0x01, 0xb8, 0xc0, 0xa8,
            0x01, 0x70, 0xa1, 0x7f, 0x00, 0x17, 0x33, 0xea, 0x37, 0xf6, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0x39, 0x08, 0x84, 0xa7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x0f,
            0x15, 0xae, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06
        ];

        b.iter(|| {
            get_socket_token(&test_packet[..]);
        });
    }
}
