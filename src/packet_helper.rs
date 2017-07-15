use std::io::{Result, Error, ErrorKind};

use pnet::packet::{tcp, Packet, ipv4, udp};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, TcpFlags, TcpOption};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};

use tcp::session::TCPSession;
use udp::session::UDPSession;

// Consts.
pub const IP_HEADER_LENGTH:usize = 20;
pub const TCP_MIN_HEADER_LENGTH:usize = 20;
pub const UDP_HEADER_LENGTH:usize = 8;

pub fn build_syn_ack(tcp_session: &TCPSession) -> Vec<u8> {
    build_tcp_packet(tcp_session, (TcpFlags::SYN | TcpFlags::ACK), None, None)
}

pub fn build_ack(tcp_session: &TCPSession, sequence_number: u32) -> Vec<u8> {
    build_tcp_packet(tcp_session, TcpFlags::ACK, None, Some(sequence_number))
}

pub fn build_fin_ack(tcp_session: &TCPSession) -> Vec<u8> {
    build_tcp_packet(tcp_session, (TcpFlags::FIN | TcpFlags::ACK), None, None)
}

pub fn build_data_packet(tcp_session: &TCPSession, packet: &[u8], sequence_number: u32) -> Vec<u8> {
    build_tcp_packet(tcp_session, TcpFlags::ACK, Some(packet), Some(sequence_number))
}

pub fn build_rst(tcp_session: &TCPSession) -> Vec<u8> {
    build_tcp_packet(tcp_session, TcpFlags::RST, None, None)
}

pub fn build_tcp_packet(tcp_session: &TCPSession, flags: u16, payload: Option<&[u8]>, sequence_number: Option<u32>) -> Vec<u8> {
    let options_length = 12;
    let payload_length = payload.map(|p| p.len()).unwrap_or(0);
    let length = IP_HEADER_LENGTH + TCP_MIN_HEADER_LENGTH + options_length + payload_length;
    let mut new_packet = vec![0u8; length];

    {
        let mut new_ip_header = MutableIpv4Packet::new(&mut new_packet[..]).unwrap();
        new_ip_header.set_version(4);
        new_ip_header.set_header_length(5);
        new_ip_header.set_ttl(64);
        new_ip_header.set_total_length(length as u16);
        new_ip_header.set_source(tcp_session.destination_ip); // Flipped from original.
        new_ip_header.set_destination(tcp_session.source_ip); // Flipped from original.
        new_ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        let checksum = ipv4::checksum(&new_ip_header.to_immutable());
        new_ip_header.set_checksum(checksum);
    }

    {
        let mut new_tcp_header = MutableTcpPacket::new(&mut new_packet[IP_HEADER_LENGTH..]).unwrap();
        new_tcp_header.set_source(tcp_session.destination_port); // Flipped from original.
        new_tcp_header.set_destination(tcp_session.source_port); // Flipped from original.

        if let Some(sequence_number) = sequence_number {
            new_tcp_header.set_sequence(sequence_number);
        } else {
            new_tcp_header.set_sequence(tcp_session.sequence_number);
        }

        if flags == TcpFlags::RST {
            new_tcp_header.set_acknowledgement(0); // RST must have Acknowledgement of 0.
        }
        else {
            new_tcp_header.set_acknowledgement(tcp_session.acknowledgement_number);
        }

        new_tcp_header.set_data_offset(8);
        new_tcp_header.set_flags(flags);
        new_tcp_header.set_window(14656);
        new_tcp_header.set_urgent_ptr(0x0000);

        let options = vec![
            TcpOption::mss(1460),
            TcpOption::wscale(6),
            TcpOption::nop(),
        ];

        new_tcp_header.set_options(&options);

        if let Some(payload) = payload {
            new_tcp_header.set_payload(payload);
        }

        let tcp_checksum = tcp::ipv4_checksum(&new_tcp_header.to_immutable(),
                                          tcp_session.source_ip,
                                          tcp_session.destination_ip,
                                          IpNextHeaderProtocols::Tcp);
        new_tcp_header.set_checksum(tcp_checksum);
    }

    new_packet
}

#[derive(PartialEq, Debug, Clone)]
pub enum TCP {
    Data(Vec<u8>, u32), // Payload, SEQ
    ACK(u32), // SEQ
    FINACK,
    SYN,
    SYNACK,
    RST
}


#[derive(PartialEq, Debug, Clone)]
pub enum PacketType {
    TCP(TCP),
    UDP(Vec<u8>),
}

pub fn get_packet_type(packet: &[u8]) -> Result<PacketType> {
    let ip_header = try!(Ipv4Packet::new(&packet[..]).ok_or(Error::new(ErrorKind::Other, format!("INVALID PACKET: {:?}", &packet))));
    let payload = ip_header.payload();

    match ip_header.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp      => Ok(PacketType::TCP(get_tcp_type(payload))),
        IpNextHeaderProtocols::Udp      => Ok(get_udp_type(&payload[..])),
        _                               => Err(Error::new(ErrorKind::Other, format!("INVALID PACKET: {:?}", &packet))),
    }
}

/// Uses bit-mask to determine whether specific flags have been set.
/// See [this article](https://code.tutsplus.com/articles/understanding-bitwise-operators--active-11301) for
/// an explanation.
fn get_tcp_type(packet: &[u8]) -> TCP {
    let tcp_header = TcpPacket::new(packet).unwrap();
    let payload = tcp_header.payload().to_vec();

    if payload.len() > 0 {
        return TCP::Data(payload, 0);
    }

    let flags = tcp_header.get_flags();

    if TcpFlags::RST & flags > 0 {
        return TCP::RST;
    }

    let finack = TcpFlags::FIN | TcpFlags::ACK;
    if finack & flags == finack {
        return TCP::FINACK;
    }

    let synack = TcpFlags::SYN | TcpFlags::ACK;
    if synack & flags == synack {
        return TCP::SYNACK;
    }

    if TcpFlags::SYN & flags > 0 {
        return TCP::SYN;
    }

    if TcpFlags::ACK & flags > 0 {
        return TCP::ACK(0);
    }

    // We've got no idea what this is, return RST (error)
    TCP::RST
}

fn get_udp_type(packet: &[u8]) -> PacketType {
    let udp_header = UdpPacket::new(&packet).unwrap();
    let data = udp_header.payload().to_vec();

    PacketType::UDP(data)
}

pub fn build_udp_packet(data: Vec<u8>, udp_session: &UDPSession) -> Vec<u8> {
    let udp_length = data.len();
    let length = IP_HEADER_LENGTH + UDP_HEADER_LENGTH + udp_length;
    let mut new_packet = vec![0u8; length];

    {
        let mut new_ip_header = MutableIpv4Packet::new(&mut new_packet[..]).unwrap();
        new_ip_header.set_version(4);
        new_ip_header.set_header_length(5);
        new_ip_header.set_ttl(64);
        new_ip_header.set_total_length(length as u16); // Hrm..
        new_ip_header.set_source(udp_session.destination_ip); // Flipped from original.
        new_ip_header.set_destination(udp_session.source_ip); // Flipped from original.
        new_ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);

        let checksum = ipv4::checksum(&new_ip_header.to_immutable());
        new_ip_header.set_checksum(checksum);
    }

    {
        let mut new_udp_header = MutableUdpPacket::new(&mut new_packet[IP_HEADER_LENGTH..]).unwrap();
        new_udp_header.set_source(udp_session.destination_port); // Flipped from original.
        new_udp_header.set_destination(udp_session.source_port); // Flipped from original.
        new_udp_header.set_length((UDP_HEADER_LENGTH + udp_length) as u16);
        new_udp_header.set_payload(&data[..]);

        let udp_checksum = udp::ipv4_checksum(&new_udp_header.to_immutable(),
                                          udp_session.source_ip,
                                          udp_session.destination_ip,
                                          IpNextHeaderProtocols::Udp);
        new_udp_header.set_checksum(udp_checksum);
    }

    new_packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use test_utils::*;

    use udp::session::UDPSession;

    use mio::udp::UdpSocket;
    use mio::Token;

    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::{TcpPacket, TcpFlags};
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::Packet;

    #[test]
    fn test_build_syn_ack() {
        let test_session = test_session();
        let test_syn_ack = build_syn_ack(&test_session);

        let ip_header = Ipv4Packet::new(&test_syn_ack).unwrap();
        let tcp_header = TcpPacket::new(&ip_header.payload()[..]).unwrap();

        assert_eq!(ip_header.packet().len() as u16, ip_header.get_total_length());
        assert_eq!(ip_header.get_source(), test_session.destination_ip); // Should be flipped.
        assert_eq!(ip_header.get_destination(), test_session.source_ip); // Should be flipped.
        assert_eq!(tcp_header.get_source(), test_session.destination_port); // Should be flipped.
        assert_eq!(tcp_header.get_destination(), test_session.source_port); // Should be flipped.
        assert_eq!(tcp_header.get_sequence(), test_session.sequence_number); // Should be remote
        assert_eq!(tcp_header.get_acknowledgement(), test_session.acknowledgement_number); // Should be local.
        assert_eq!(tcp_header.get_flags(), TcpFlags::SYN | TcpFlags::ACK); // Should be remote
        assert_eq!(tcp_header.get_checksum(), 64562);
    }

    #[test]
    fn test_build_data_packet() {
        let test_session = test_session();
        let expected_payload = vec![0xc0, 0xff, 0xee, 0x15, 0xf0, 0x0d];
        let test_sequence_number = 5;
        let data_packet = build_data_packet(&test_session, &expected_payload[..], test_sequence_number);

        let ip_header = Ipv4Packet::new(&data_packet).unwrap();
        let tcp_header = TcpPacket::new(&ip_header.payload()[..]).unwrap();

        println!("{:?}", &data_packet[IP_HEADER_LENGTH..].iter().map(|x| format!("0x{:02x}", x)).collect::<Vec<String>>());

        assert_eq!(ip_header.packet().len() as u16, ip_header.get_total_length());
        assert_eq!(ip_header.get_source(), test_session.destination_ip); // Should be flipped.
        assert_eq!(ip_header.get_destination(), test_session.source_ip); // Should be flipped.
        assert_eq!(tcp_header.get_source(), test_session.destination_port); // Should be flipped.
        assert_eq!(tcp_header.get_destination(), test_session.source_port); // Should be flipped.
        assert_eq!(tcp_header.get_acknowledgement(), test_session.acknowledgement_number); // Should be incremeneted
        assert_eq!(tcp_header.get_sequence(), test_sequence_number); // Should be remote
        assert_eq!(tcp_header.get_flags(), TcpFlags::ACK);
        assert_eq!(tcp_header.payload(), &expected_payload[..]);
    }

    #[test]
    fn test_build_ack() {
        let test_session = test_session();
        let test_sequence_number = 42;
        let test_ack = build_ack(&test_session, test_sequence_number);

        let ip_header = Ipv4Packet::new(&test_ack).unwrap();
        let tcp_header = TcpPacket::new(&ip_header.payload()[..]).unwrap();

        assert_eq!(ip_header.packet().len() as u16, ip_header.get_total_length());
        assert_eq!(ip_header.get_source(), test_session.destination_ip); // Should be flipped.
        assert_eq!(ip_header.get_destination(), test_session.source_ip); // Should be flipped.
        assert_eq!(tcp_header.get_source(), test_session.destination_port); // Should be flipped.
        assert_eq!(tcp_header.get_destination(), test_session.source_port); // Should be flipped.
        assert_eq!(tcp_header.get_sequence(), test_sequence_number);
        assert_eq!(tcp_header.get_acknowledgement(), test_session.acknowledgement_number);
        assert_eq!(tcp_header.get_flags(), TcpFlags::ACK); // Should be ACK
        assert_eq!(tcp_header.get_checksum(), 64522);
    }

    #[test]
    fn test_build_fin_ack() {
        let test_session = test_session();
        let test_ack = build_fin_ack(&test_session);

        let ip_header = Ipv4Packet::new(&test_ack).unwrap();
        let tcp_header = TcpPacket::new(&ip_header.payload()[..]).unwrap();

        assert_eq!(ip_header.packet().len() as u16, ip_header.get_total_length());
        assert_eq!(ip_header.get_source(), test_session.destination_ip); // Should be flipped.
        assert_eq!(ip_header.get_destination(), test_session.source_ip); // Should be flipped.
        assert_eq!(tcp_header.get_source(), test_session.destination_port); // Should be flipped.
        assert_eq!(tcp_header.get_destination(), test_session.source_port); // Should be flipped.
        assert_eq!(tcp_header.get_sequence(), test_session.sequence_number);
        assert_eq!(tcp_header.get_acknowledgement(), test_session.acknowledgement_number);
        assert_eq!(tcp_header.get_flags(), TcpFlags::FIN | TcpFlags::ACK); // Should be FIN/ACK
        assert_eq!(tcp_header.get_checksum(), 64563);
    }

    #[test]
    fn test_build_rst() {
        let mut session = test_session();
        session.acknowledgement_number = 1234; // Set non-zero.

        let rst = build_rst(&session);
        let ip_header = Ipv4Packet::new(&rst).unwrap();
        let tcp_header = TcpPacket::new(&ip_header.payload()[..]).unwrap();

        assert_eq!(tcp_header.get_acknowledgement(), 0);

        let flags = tcp_header.get_flags();
        assert_eq!(flags, TcpFlags::RST);
    }


    #[test]
    fn test_get_packet_type() {
        let test_tcp_packet_with_payload = vec![
        0x45, 0x10, 0x00, 0x43, 0xa8, 0x50, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x70, 0xc0, 0xa8, 0x01, 0x70, 0x00, 0x17, 0xd0, 0x9a, 0x45, 0x56, 0xcd, 0xb9,
        0xfa, 0xab, 0x8b, 0xcc, 0x80, 0x18, 0x31, 0xd7, 0x84, 0x66, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x21, 0x31, 0x21, 0xd4, 0x21, 0x31, 0x21, 0xd1, 0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20, 0xff, 0xfd,
        0x23, 0xff, 0xfd, 0x27, 0xff, 0xfd, 0x24];

        let expected_tcp_payload = vec![0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20, 0xff, 0xfd,
        0x23, 0xff, 0xfd, 0x27, 0xff, 0xfd, 0x24];

        assert_eq!(get_packet_type(&test_tcp_packet_with_payload[..]).unwrap(), PacketType::TCP(TCP::Data(expected_tcp_payload, 0)));

        let test_udp_packet_with_payload = vec![
        0x45, 0x00, 0x00, 0x23, 0xdd, 0xb1, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xf5, 0xe2, 0x04, 0xd2, 0x00, 0x0f, 0xfe, 0x22,
        0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x0a];

        let expected_udp_payload = vec![0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x0a];

        assert_eq!(get_packet_type(&test_udp_packet_with_payload[..]).unwrap(), PacketType::UDP(expected_udp_payload));

        let test_packet_with_1_byte_payload = vec![
        0x45, 0x00, 0x00, 0x29, 0x1b, 0x1b, 0x40, 0x00, 0x40, 0x06, 0x49, 0x9a, 0x0a, 0x01, 0x0a, 0x01,
        0xc0, 0xa8, 0x01, 0x70, 0x97, 0x7f, 0x00, 0x17, 0x61, 0xe4, 0x56, 0x86, 0x2b, 0x0d, 0xf9, 0x53,
        0x50, 0x18, 0x00, 0xe5, 0xf9, 0x69, 0x00, 0x00, 0x6b];

        let expected_1_byte_payload = vec![0x6b];
        assert_eq!(get_packet_type(&test_packet_with_1_byte_payload[..]).unwrap(), PacketType::TCP(TCP::Data(expected_1_byte_payload, 0)));

        let test_ack = vec![
            0x45, 0x00, 0x00, 0x28, 0x71, 0xfd, 0x40, 0x00, 0x40, 0x06, 0xf2, 0xb8, 0x0a, 0x01, 0x0a, 0x01,
            0xc0, 0xa8, 0x01, 0x70, 0x97, 0x1f, 0x00, 0x17, 0xac, 0x8c, 0x1a, 0x35, 0x7b, 0x56, 0x0a, 0xe8,
            0x50, 0x10, 0x00, 0xe5, 0xd6, 0x34, 0x00, 0x00];
        assert_eq!(get_packet_type(&test_ack[..]).unwrap(), PacketType::TCP(TCP::ACK(0)));

        let test_fin_ack = vec![0x45, 0x00, 0x00, 0x28, 0x56, 0x01, 0x40, 0x00, 0x40, 0x06, 0x0e, 0xb5, 0x0a, 0x01, 0x0a, 0x01,
            0xc0, 0xa8, 0x01, 0x70, 0x98, 0x95, 0x00, 0x17, 0x97, 0xdc, 0x59, 0x1e, 0xce, 0xe6, 0xde, 0xf3,
            0x50, 0x11, 0x00, 0xe5, 0xd6, 0x34, 0x00, 0x00];
        assert_eq!(get_packet_type(&test_fin_ack[..]).unwrap(), PacketType::TCP(TCP::FINACK));

        let syn_packet = vec![69, 0, 0, 60, 64, 140, 64, 0, 64, 6, 41, 220, 10, 1, 10, 1, 220, 244,
        223, 93, 164, 117, 1, 187, 160, 89, 218, 74, 0, 0, 0, 0, 160, 2, 57, 8, 114, 90, 0, 0, 2, 4, 5,
        180, 4, 2, 8, 10, 16, 175, 154, 198, 0, 0, 0, 0, 1, 3, 3, 6];
        assert_eq!(get_packet_type(&syn_packet[..]).unwrap(), PacketType::TCP(TCP::SYN));

        let rst_packet = vec![69, 0, 0, 40, 0, 0, 64, 0, 64, 6, 19, 79, 192, 168, 1, 184, 220, 244,
        136, 44, 223, 99, 1, 187, 72, 26, 226, 62, 0, 0, 0, 0, 80, 4, 0, 0, 124, 231, 0, 0];
        assert_eq!(get_packet_type(&rst_packet[..]).unwrap(), PacketType::TCP(TCP::RST));

        let another_rst_packet = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x13, 0x44, 0xc0, 0xa8, 0x01, 0xb8,
        0xdc, 0xf4, 0x88, 0x37, 0xe3, 0x7f, 0x01, 0xbb, 0xf1, 0x83, 0x31, 0xc1, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x04, 0x00, 0x00, 0x7f, 0xd4, 0x00, 0x00];
        assert_eq!(get_packet_type(&another_rst_packet[..]).unwrap(), PacketType::TCP(TCP::RST));

        let killer_packet = vec![69, 0, 0, 40, 53, 184, 64, 0, 64, 6, 81, 150, 10, 1, 10, 1, 216, 58,
        199, 69, 230, 215, 1, 187, 156, 92, 243, 58, 251, 135, 22, 28, 80, 25, 1, 82, 113, 41, 0, 0];
        assert_eq!(get_packet_type(&killer_packet[..]).unwrap(), PacketType::TCP(TCP::FINACK));
    }

    #[test]
    fn test_build_udp_packet() {
        use std::collections::VecDeque;

        let data = vec![19, 178, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 3, 119, 119, 119, 6, 103, 111, 111, 103,
        108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 1, 33, 0, 4, 216, 58, 220,
        132];
        let source_port = 123;
        let destination_port = 456;
        let source_ip = Ipv4Addr::new(192,168,0,1);
        let destination_ip = Ipv4Addr::new(192,168,0,2);

        let test_session = UDPSession {
            source_port: source_port,
            destination_port: destination_port,
            source_ip: source_ip,
            destination_ip: destination_ip,
            socket: UdpSocket::v4().unwrap(),
            timeout: None,
            write_queue: VecDeque::new(),
            token: Token(1),
        };

        let udp_packet = build_udp_packet(data.clone(), &test_session);

        let ip_header = Ipv4Packet::new(&udp_packet[..]).unwrap();
        let udp_header = UdpPacket::new(&ip_header.payload()[..]).unwrap();

        assert_eq!(ip_header.get_source(), destination_ip);
        assert_eq!(ip_header.get_destination(), source_ip);
        assert_eq!(udp_header.get_source(), destination_port);
        assert_eq!(udp_header.get_destination(), source_port);
        assert_eq!(udp_header.get_checksum(), 58136);
        assert_eq!(udp_header.get_length(), (UDP_HEADER_LENGTH + data.len()) as u16);
        assert_eq!(udp_header.payload(), &data[..]);
    }
}
