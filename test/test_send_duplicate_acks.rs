#[allow(unused_must_use)]
use super::*;

use std::io::prelude::*;
use mio::*;
use mio::tcp::TcpStream;
use std::net;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::ipv4::{MutableIpv4Packet};
use traxi::tcp::session::TCPState;

#[test]
#[allow(unused_must_use)]
/// RFC 5681 3.2: A TCP receiver SHOULD send an immediate duplicate ACK when an out-
/// of-order segment arrives.  The purpose of this ACK is to inform the sender that a
/// segment was received out-of-order and which sequence number is expected.
fn test_send_duplicate_acks() {
    init_logging();
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    let token = Token(8944366915402951162);
    let mut buf = [0u8; 2048];

    let initial_acknowledgement_number = 10;
    let test_data_length = 10;

    let l = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let socket = TcpStream::connect(&addr).unwrap();

    // Create a fake session and insert it into the map.
    let mut session = test_session();
    session.state = TCPState::Established;
    session.token = token.clone();
    session.acknowledgement_number = initial_acknowledgement_number;
    session.socket = Some(socket);
    test_traxi_tunnel.tcp_sessions.insert(token, session);


    // Send the first data segment with a legit sequence number.
    {
        send_data(&mut fifo, initial_acknowledgement_number);
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Read first data segment");
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Write data to socket");
    }

    // Assert that session.acknowledgement_number has been incremented by the length of our data
    // segment.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Session not found!");
        assert_eq!(session.acknowledgement_number, initial_acknowledgement_number + test_data_length);
    }

    {
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send first ACK");
        let len = fifo.read(&mut buf).expect("Couldn't read first ACK");
        let header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(header.get_acknowledgement(), initial_acknowledgement_number + test_data_length);
    }

    // Send a data segment with a too high sequence number.
    {
        send_data(&mut fifo, 9000);
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Read invalid data segment");
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Queue ACK");
    }

    // Assert that session.acknowledgement_number was not incremented.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Session not found!");
        assert_eq!(session.acknowledgement_number, initial_acknowledgement_number + test_data_length);
    }

    {
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send duplicate ACK");
        let len = fifo.read(&mut buf).expect("Couldn't read duplicate ACK");
        let header = TcpPacket::new(&buf[20..len]).unwrap();

        // Assert this ACK is a duplicate.
        assert_eq!(header.get_acknowledgement(), initial_acknowledgement_number + test_data_length);
    }

}

fn send_data(fifo: &mut Io, sequence_number: u32) {
    let mut first_data_segment = vec![
        0x45, 0x00, 0x00, 0x28, 0x32, 0xbd, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xf0, 0x0a, 0x01, 0x0a, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x27, 0xb4, 0x89, 0x32, 0x4c,
        0x50, 0x10, 0x00, 0xe5, 0x79, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00];
    {
        let mut ip_header = MutableIpv4Packet::new(&mut first_data_segment[..]).unwrap();
        ip_header.set_total_length(62);
    }

    {
        let mut tcp_header = MutableTcpPacket::new(&mut first_data_segment[20..]).unwrap();
        tcp_header.set_sequence(sequence_number);
    }

    fifo.write(&first_data_segment[..]).expect("Unable to write data");
}
