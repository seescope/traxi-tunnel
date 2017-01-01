use super::*;
use mio::*;
use std::io::prelude::*;
use pnet::packet::tcp::TcpPacket;

#[test]
#[allow(unused_must_use)]
fn test_chunk_data() {
    init_logging();

    const TEST_MTU:u32 = 1337;
    let header_size:u32 = 52;
    let mut buf = [0u8; 4000]; 
    let token = Token(5);
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    // Create a fake session and insert it into the map.
    let mut session = test_session();
    session.receiver_window = 4001; // Make sure the window is big enough to send our test data.
    session.sequence_number = 1;
    test_traxi_tunnel.tcp_sessions.insert(token, session);

    {
        // Send 9999 bytes of data. This should be too big for the MSS.
        let test_data = [1u8; 4000];
        let mut session = test_traxi_tunnel.tcp_sessions.get_mut(&token).expect("Session not found");
        session.send_data(&test_data[..], &mut test_event_loop);
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Process data");

    // We sent 4000 bytes of data, so we should expect to receive 4000 / (1337 + 52) packets
    for n in 0..2 {
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, &format!("Send data {}", n));
        let len = fifo.read(&mut buf[..]).expect("Can't read");
        assert_eq!(len as u32, TEST_MTU + header_size);

        let tcp_header = TcpPacket::new(&buf[20..]).unwrap();
        assert_eq!(tcp_header.get_sequence(), 1 + TEST_MTU * n);
    }

    // Last chunk
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send last chunk");
    let len = fifo.read(&mut buf[..]).unwrap();
    assert_eq!(len as u32, 4000 % TEST_MTU + header_size);

    let tcp_header = TcpPacket::new(&buf[20..]).unwrap();
    assert_eq!(tcp_header.get_sequence(), 1 + TEST_MTU * 2);
}
