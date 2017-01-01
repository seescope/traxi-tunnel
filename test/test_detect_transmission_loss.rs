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
fn test_detect_transmission_loss() {
    init_logging();

    let mut buf = [0u8; 4000]; 
    let token = Token(8944366915402951162);
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    // Create a fake session and insert it into the map.
    let mut session = test_session();
    session.state = TCPState::Established;
    session.token = token.clone();
    session.sequence_number = 1;
    session.unacknowledged = 1;
    test_traxi_tunnel.tcp_sessions.insert(token, session);

    // Send the first packet.
    {
        let first_packet = [1; 50];
        let mut session = test_traxi_tunnel.tcp_sessions.get_mut(&token).expect("Couldn't find session!");
        session.send_data(&first_packet[..], &mut test_event_loop);
    }

    // Process the packet through the tunnel.
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Queue first data");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send first data");

    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Couldn't find session!");
        let len = fifo.read(&mut buf).expect("Couldn't read first data");
        let header = TcpPacket::new(&buf[20..len]).unwrap();

        // Assert the sequence number and unacknowledged is correct.
        assert_eq!(header.get_sequence(), 1, "Packet sequence incorrect");
        assert_eq!(session.unacknowledged, 1, "Unacknowledged incorrect");
    }


    // Send back our first ACK for SEQ 1.
    {
        let first_ack_number = 51;
        let mut first_ack = vec![
            0x45, 0x00, 0x00, 0x28, 0x32, 0xbd, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xf0, 0x0a, 0x01, 0x0a, 0x01,
            0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x27, 0xb4, 0x89, 0x32, 0x4c,
            0x50, 0x10, 0x00, 0xe5, 0x79, 0x3d, 0x00, 0x00];
        {
            let mut tcp_header = MutableTcpPacket::new(&mut first_ack[20..]).unwrap();
            tcp_header.set_acknowledgement(first_ack_number); // Acknowledge SEQ 1;
        }

        fifo.write(&first_ack[..]);
        spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Read ACK 51");

        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Couldn't find session!");

        // Assert that UNA has increased to SEQ 1.
        assert_eq!(session.unacknowledged, first_ack_number);
    }

    // Send second data.
    {
        let second_packet = [1; 50];
        let mut session = test_traxi_tunnel.tcp_sessions.get_mut(&token).expect("Couldn't find session!");
        session.send_data(&second_packet[..], &mut test_event_loop);
    }

    // Process through the tunnel.
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Queue second data");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Send second data");

    // Assert SEQ and UNA are correct on this packet.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Couldn't find session!");
        let len = fifo.read(&mut buf).expect("Couldn't read second data");
        let header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(header.get_sequence(), 51, "Packet sequence incorrect");
        assert_eq!(session.unacknowledged, 51, "Unacknowledged incorrect");
    }

    // Send 3 **DUPLICATE ACKs** for SEQ 1.
    {
        let first_ack_number = 51;
        let mut first_ack = vec![
            0x45, 0x00, 0x00, 0x28, 0x32, 0xbd, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xf0, 0x0a, 0x01, 0x0a, 0x01,
            0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x27, 0xb4, 0x89, 0x32, 0x4c,
            0x50, 0x10, 0x00, 0xe5, 0x79, 0x3d, 0x00, 0x00];
        {
            let mut tcp_header = MutableTcpPacket::new(&mut first_ack[20..]).unwrap();
            tcp_header.set_acknowledgement(first_ack_number); // Acknowledge SEQ 1 again.
        }

        for n in 0..3 {
            fifo.write(&first_ack[..]);
            spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, &format!("Read duplicate ACK {}", n));
        }

        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Couldn't find session!");

        // Assert UNA is still at SEQ 51.
        assert_eq!(session.unacknowledged, first_ack_number);

        // Assert we've entered Fast Retransmit.
        assert!(session.entered_fast_retransmit.is_some());
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Queue SEQ51");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Re-transmit SEQ51");

    // Receive retransmitted packet for SEQ 51.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Couldn't find session!");
        let len = fifo.read(&mut buf).expect("Couldn't read retransmitted data");
        let header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(header.get_sequence(), 51, "Packet sequence incorrect");
        assert_eq!(session.unacknowledged, 51, "Unacknowledged incorrect");
    }

    // Send ACK for SEQ 51.
    {
        let second_ack_number = 101;
        let mut second_ack = vec![
            0x45, 0x00, 0x00, 0x28, 0x32, 0xbd, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xf0, 0x0a, 0x01, 0x0a, 0x01,
            0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x27, 0xb4, 0x89, 0x32, 0x4c,
            0x50, 0x10, 0x00, 0xe5, 0x79, 0x3d, 0x00, 0x00];
        {
            let mut tcp_header = MutableTcpPacket::new(&mut second_ack[20..]).unwrap();
            tcp_header.set_acknowledgement(second_ack_number); // Acknowledge SEQ 51.
        }

        {
            fifo.write(&second_ack[..]);
            spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Read ACK 101");
            
            let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Couldn't find session!");
            // Assert UNA is now at 101.
            assert_eq!(session.unacknowledged, second_ack_number);

            // Assert we have left Fast Retransmit
            assert!(session.entered_fast_retransmit.is_none());
        }
    }
}
