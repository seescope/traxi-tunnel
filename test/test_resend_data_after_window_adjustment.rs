use super::*;
use mio::*;
use std::io::prelude::*;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use traxi::tcp::session::TCPState;

#[test]
#[allow(unused_must_use)]
/// Per RFC 1122, if a TCP segment is not within the send window, the packet must be queued until
/// such time as the window expands to sufficiently allow it to open.
/// In this test we set an extremely low window (1), pump packets into the session and wait for
/// them to be queued. We then send an ACK with a larger window, such that the window size will be
/// updated. We then expect for the queued data to be sent with the correct SEQ numbers.
fn test_resend_data_after_window_adjustment() {
    init_logging();

    const TEST_MTU:usize = 1337;
    let header_size = 52;
    let mut buf = [0u8; 4000]; 
    let token = Token(8944366915402951162);
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    // Create a fake session and insert it into the map.
    let mut session = test_session();
    session.state = TCPState::Established;
    session.token = token.clone();
    session.receiver_window = 1; // Make the window artificially small.
	session.sequence_number = 2; // Make the sequence number AFTER the window.
    let mut sequence_number = session.sequence_number;

    test_traxi_tunnel.tcp_sessions.insert(token, session);

    {
        // Send 9999 bytes of data. This will be too big for the window, and will get queued.
        let test_data = [1u8; 4000];
        let mut session = test_traxi_tunnel.tcp_sessions.get_mut(&token).expect("Session not found");
        session.send_data(&test_data[..], &mut test_event_loop);
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Read data from socket");

    {
        // Assert we queued 3 packets.
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Sesssion not found");
        assert_eq!(session.read_queue.len(), 3);
    }

    // Send a window update to the client, expanding its receiver_window.
    let mut window_update = vec![
        0x45, 0x00, 0x00, 0x28, 0x32, 0xbd, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xf0, 0x0a, 0x01, 0x0a, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x27, 0xb4, 0x89, 0x32, 0x4c,
        0x50, 0x10, 0x00, 0xe5, 0x79, 0x3d, 0x00, 0x00];
    {
        let mut tcp_header = MutableTcpPacket::new(&mut window_update[20..]).unwrap();
        tcp_header.set_window(4001); // Update window to 4001.
    }

    fifo.write(&window_update[..]);
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Read window update");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Queue packets");

    // We sent 4000 bytes of data, so we should expect to receive 4000 / (1337 + 52) packets
    for n in 0..2 {
        // Check packet size
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, &format!("Send data {}", n));
        let len = fifo.read(&mut buf[..]).expect("Can't read");
        assert_eq!(len, TEST_MTU + header_size);

        // Check sequence number.
        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        let packet_sequence_number = tcp_header.get_sequence();
        assert_eq!(sequence_number, packet_sequence_number);

        sequence_number += (len - header_size) as u32;
    }

    // Last chunk
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send last chunk");
    let len = fifo.read(&mut buf[..]).unwrap();
    assert_eq!(len, 4000 % TEST_MTU + header_size);

}
