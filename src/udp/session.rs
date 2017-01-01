use tunnel::{TraxiTunnel, TraxiMessage, Environment};
use packet_helper::PacketType;

use std::collections::VecDeque;
use std::net::{SocketAddr, Ipv4Addr};
use std::os::unix::io::{AsRawFd};
use std::io::{Result, Error, ErrorKind};

use mio::udp::UdpSocket;
use mio::{Timeout, EventLoop, Token, EventSet, PollOpt};

use pnet::packet::Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::ipv4::Ipv4Packet;

#[derive(Debug)]
pub struct UDPSession {
    pub source_port: u16,
    pub destination_port: u16,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub socket: UdpSocket,
    pub timeout: Option<Timeout>,
    pub write_queue: VecDeque<(SocketAddr, Vec<u8>)>,
    pub token: Token,
}

impl UDPSession {
    pub fn new<T: Environment>(packet: &[u8], environment: &T, token: Token) -> Result<UDPSession> {
        let ip_header = Ipv4Packet::new(packet).unwrap();
        let udp_header = UdpPacket::new(&ip_header.payload()[..]).unwrap();

        let destination_ip = ip_header.get_destination();
        let destination_port = udp_header.get_destination();
        let source_ip = ip_header.get_source();
        let source_port = udp_header.get_source();

        let socket = try!(UdpSocket::v4());
        environment.protect(socket.as_raw_fd());

        Ok(UDPSession{
            source_ip: source_ip,
            destination_ip: destination_ip,
            source_port: source_port,
            destination_port: destination_port,
            socket: socket,
            timeout: None,
            write_queue: VecDeque::new(),
            token: token,
        })
    }

    pub fn writable<T: Environment>(&mut self, event_loop: &mut EventLoop<TraxiTunnel<T>>) -> Result<()> {
        // Get the first packet and target address from the write queue.
        let (target_address, data) = try!(self.write_queue.pop_front().ok_or(
            Error::new(ErrorKind::Other, format!("UDP SESSION {}| Ready but write queue empty!", self.token.as_usize()))
        ));

        // Attempt to send the data to target address.
        let written = try!(self.socket.send_to(&data[..], &target_address));
        debug!("UDP SESSION {}| Wrote {:?}", self.token.as_usize(), written);

        // Register for reads.
        let mut interest = EventSet::readable();

        // If there are more packets left in the write queue, register for writes as well.
        if self.write_queue.len() > 0 {
            interest.insert(EventSet::writable());
        }

        event_loop.reregister(&self.socket, self.token, interest, PollOpt::edge() | PollOpt::oneshot())
    }

    #[allow(unused_must_use)]
    pub fn readable<T: Environment>(&mut self, event_loop: &mut EventLoop<TraxiTunnel<T>>) -> Result<()> {
        // Prepare a buffer for reading.
        let mut buf = [0u8; 4068];

        // Read from the UDP socket.
        if let Some((read, _)) = try!(self.socket.recv_from(&mut buf[..])) {
            debug!("UDP SESSION READ {}| DATA: {:?}", self.token.as_usize(), &buf[..read]);
            let sender = event_loop.channel();
            sender.send(TraxiMessage::QueuePacket(PacketType::UDP(buf[..read].to_vec()), self.token));
        } else {
            error!("UDP SESSION {}| Ready but read 0 bytes!", self.token.as_usize());
        }

        event_loop.reregister(&self.socket, self.token, EventSet::readable(), PollOpt::edge())
    }

}

#[cfg(test)]
use test_utils::FakeEnvironment;

#[test]
fn test_new_udp_session() {
    let test_packet = vec![
    0x45, 0x00, 0x00, 0x23, 0xdd, 0xb1, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xf5, 0xe2, 0x04, 0xd2, 0x00, 0x0f, 0xfe, 0x22,
    0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x0a];

    let expected_destination_ip = Ipv4Addr::new(127,0,0,1);
    let expected_source_ip = Ipv4Addr::new(127,0,0,1);
    let expected_destination_port = 1234;
    let expected_source_port = 62946;
    let fake_environment = FakeEnvironment;
    let token = Token(123);

    let session = UDPSession::new(&test_packet[..], &fake_environment, token).unwrap();

    assert_eq!(session.source_ip, expected_source_ip);
    assert_eq!(session.destination_ip, expected_destination_ip);
    assert_eq!(session.source_port, expected_source_port);
    assert_eq!(session.destination_port, expected_destination_port);
}
