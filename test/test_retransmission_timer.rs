use super::*;
use mio::*;
use std::io::prelude::*;
use pnet::packet::tcp::TcpPacket;
use std::thread::sleep;
use std::time::Duration;

#[test]
#[ignore]
fn test_retransmission_timer() {
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
        // Send some data.
        let test_data = [1u8; 1337];
        let mut session = test_traxi_tunnel.tcp_sessions.get_mut(&token).expect("Session not found");
        session.send_data(&test_data[..], &mut test_event_loop);
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send data to queue");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Write data to tunnel");

    {
        let len = fifo.read(&mut buf[..]).expect("Can't read");
        assert_eq!(len as u32, TEST_MTU + header_size);

        let tcp_header = TcpPacket::new(&buf[20..]).unwrap();
        assert_eq!(tcp_header.get_sequence(), 1);
    }

    sleep(Duration::from_millis(1000));

    // Wake up
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Timeout");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send data to queue");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Write data to tunnel");

    {
        let len = fifo.read(&mut buf[..]).expect("Can't read");
        assert_eq!(len as u32, TEST_MTU + header_size);

        let tcp_header = TcpPacket::new(&buf[20..]).unwrap();

        // Assert this is the retransmitted packet.
        assert_eq!(tcp_header.get_sequence(), 1);

    }

    {
        let session = test_traxi_tunnel.tcp_sessions.get_mut(&token).expect("Couldn't find session!");
        // Acknowledge all outstanding packets. Rejoice! REJOICE!
        session.update_unacknowledged(1338, &mut test_event_loop);
    }

    sleep(Duration::from_millis(2000));

    // Wake up
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Timeout");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send data to queue");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Write data to tunnel");

    {
        // Assert that we did NOT retransmit again.
        let read = fifo.read(&mut buf[..]);
        assert!(read.is_err());
    }
}
