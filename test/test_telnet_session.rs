#[allow(unused_must_use)]

use super::*;

use std::io::prelude::*;
use std::str;
use traxi::tcp::session::*;
use mio::*;
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;

#[test]
#[allow(unused_must_use)]
/// This is a *full integration test* of `TraxiTunnel`. It works by creating a named pipe with
/// `#build_test_fifo` to emulate how the tunnel would work in a production environment. Then, we
/// feed raw IP packets into the FIFO so that they can be read to the tunnel - just like on a real
/// device.
///
/// However, this doesn't come without complexity. If we simply started the `event_handler` with
/// `#run`, `TraxiTunnel` would read any data that it wrote to the tunnel. It's similar to placing
/// a letter in your own letterbox, then checking to see if anyone left you a letter - you'd be
/// stuck in a loop only reading your own letters.
///
/// To get around this limitation, we freeze time by running (we call it "spinning") the `event_loop` 
/// ONCE, then manipulating the named pipe. This allows us to do things like read data from the 
/// named pipe AFTER data has been written to it so that we can avoid the loop situation described above.
///
/// This is a very complicated, and rather messy test. To help make things simpler, we print 
/// how many times the `event_loop` has been spun so far before we spin it again. 
///
/// If you're (understandably) having trouble thinking about this test, go back to the mailbox
/// analogy, and think of a person checking two mailboxes - one from the named pipe emulating the
/// device, and another from the Internet. Each time she puts something in, or takes something from
/// the mailbox, she is frozen in time and can only move again when unfrozen.
///
/// NOTE: This test may ocassionaly fail with something like: "Resource temporarily unavailable".
/// This is an unfortunate side-effect of the nature of manipulating non-blocking sockets,
/// ocassionally we perform a read when data hasn't been flushed yet. At the time of writing KR has
/// not been able to figure out how to make this test more stable - adding sleep statements etc.
/// have not yet worked.
pub fn test_telnet_session() {
    init_logging();

    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();

    let mut sequence_number;
    let mut acknowledgement_number;
    let token = Token(14957352662117401994);
    let mut buf = [0u8; 2048];

    let syn_to_server = vec![
    0x45, 0x10, 0x00, 0x40, 0x28, 0x43, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
    0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8b, 0xcb,
    0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0x84, 0x63, 0x00, 0x00, 0x02, 0x04, 0x3f, 0xd8,
    0x01, 0x03, 0x03, 0x05, 0x01, 0x01, 0x08, 0x0a, 0x21, 0x31, 0x21, 0xd1, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x02, 0x00, 0x00];

    // Start SEQ count.
    {
        let tcp_header = TcpPacket::new(&syn_to_server[20..]).unwrap();
        acknowledgement_number = tcp_header.get_sequence(); // Use remote SEQ as our ACK.
    }

    fifo.write(&syn_to_server[..]);
    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 1 - Receive ACK");
    // Assert that we've added a session, set ACK count.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        sequence_number = session.sequence_number; // Relative SEQ 0 
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 2 - Receive from Notify");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 3 - Write SYN/ACK to Tunnel");
    
    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        // Assert that we received a valid SYN/ACK.
        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), 0x12); // 0x12 == SYN/ACK.
        assert_eq!(tcp_header.get_sequence(), sequence_number);                     // Relative SEQ 0
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number + 1);   // Relative ACK 1
        acknowledgement_number += 1; // Increment for next checks.
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 4 - Receive data from server");

    let ack_to_server = vec![
    0x45, 0x10, 0x00, 0x34, 0xd8, 0xfc, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
    0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8b, 0xcc,
    0x45, 0x56, 0xcd, 0xb9, 0x80, 0x10, 0x31, 0xd7, 0x84, 0x57, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
    0x21, 0x31, 0x21, 0xd1, 0x21, 0x31, 0x21, 0xd1];

    fifo.write(&ack_to_server[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 5 - Read ACK from FIFO");
    
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        assert_eq!(session.state, TCPState::Established);
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 6 - Send data to queue");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 7 - Write data from remote back to tunnel");

    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        let expected_payload = vec![0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20, 0xff, 0xfd, 
        0x23, 0xff, 0xfd, 0x27, 0xff, 0xfd, 0x24];
        assert_eq!(tcp_header.payload(), &expected_payload[..]);
        assert_eq!(tcp_header.get_sequence(), sequence_number + 1);                 // Relative SEQ 1 
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number);       // Relative ACK 1
        sequence_number += 1; // Increment for next checks.
    }

    // Tunnel should now send an ACK back.
    let second_ack_to_server = vec![
        0x45, 0x10, 0x00, 0x34, 0x84, 0x60, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8b, 0xcc,
        0x45, 0x56, 0xcd, 0xc8, 0x80, 0x10, 0x31, 0xd6, 0x84, 0x57, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x21, 0x31, 0x21, 0xd4, 0x21, 0x31, 0x21, 0xd4
    ];

    fifo.write(&second_ack_to_server[..]);
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 7 - Read ACK from FIFO");

    // Tunnel should now send FIRST telnet data.
    let mut telnet_data_to_server = vec![
        0x45, 0x00, 0x00, 0x37, 0x71, 0xf9, 0x40, 0x00, 0x40, 0x06, 0xf2, 0xad, 
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8b, 0xcc, 
        0x45, 0x56, 0xcd, 0xc8, 0x50, 0x18, 0x00, 0xe5, 0x9b, 0xe4, 0x00, 0x00, 0xff, 0xfb, 0x18, 0xff, 
        0xfc, 0x20, 0xff, 0xfc, 0x23, 0xff, 0xfc, 0x27, 0xff, 0xfc, 0x24];
    {
        let mut tcp_header = MutableTcpPacket::new(&mut telnet_data_to_server[20..]).unwrap();
        tcp_header.set_acknowledgement(sequence_number + 15);
    }


    fifo.write(&telnet_data_to_server[..]); 

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 8 - Receive telnet data from FIFO");
    

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 9 - Send telnet data to server");
    

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 10 - Write ACK to tunnel + Read from server");
    
    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let last_read = 15;
        let last_written = 15; // Magic number.

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), 0x10); // ACK
        assert_eq!(tcp_header.get_sequence(), sequence_number + last_written);            // Relative SEQ 16 
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number + last_read); // Relative ACK 16
        sequence_number += last_written; 
        acknowledgement_number += last_read;
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 11 - Receive ACK from tunnel + Send notify of data to tunnel");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 12 - Write to FIFO");
    
    {
        let len = try_read_from_fifo(&mut fifo, &mut buf[..], &mut test_event_loop, &mut test_traxi_tunnel);
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        let expected_payload = vec![0xff, 0xfa, 0x18, 0x01, 0xff, 0xf0];
        assert_eq!(tcp_header.payload(), &expected_payload[..]);
        assert_eq!(tcp_header.get_flags(), 0x10); // ACK
        assert_eq!(tcp_header.get_sequence(), sequence_number);                     // Relative SEQ 16
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number);       // Relative ACK 16
    }

    // Write third ACK back to server.
    let third_ack_to_server = vec![
        0x45, 0x10, 0x00, 0x34, 0x7d, 0x43, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8b, 0xdb,
        0x45, 0x56, 0xcd, 0xda, 0x80, 0x10, 0x31, 0xd6, 0x84, 0x57, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x21, 0x31, 0x21, 0xd4, 0x21, 0x31, 0x21, 0xd4];
    fifo.write(&third_ack_to_server[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 13 - Receive ACK from tunnel");
    

    // Tunnel should send SECOND telnet data to server.
    let mut second_telnet_data_to_server = vec![
        0x45, 0x00, 0x00, 0x33, 0x71, 0xfa, 0x40, 0x00, 0x40, 0x06, 0xf2, 0xb0, 
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8b, 0xea,
        0x7b, 0x56, 0x0a, 0x8f, 0x50, 0x18, 0x00, 0xe5, 0x99, 0x36, 0x00, 0x00, 0xff, 0xfa, 0x18, 0x00, 
        0x6c, 0x69, 0x6e, 0x75, 0x78, 0xff, 0xf0];
    {
        let mut tcp_header = MutableTcpPacket::new(&mut second_telnet_data_to_server[20..]).unwrap();
        tcp_header.set_acknowledgement(sequence_number);
        tcp_header.set_sequence(acknowledgement_number);
    }

    fifo.write(&second_telnet_data_to_server[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 14 - Read data from tunnel");
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 15 - Write data to server");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 16 - Write ACK");

    {
        let last_read = 11;
        let last_written = 6;
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), 0x10); // ACK.
        assert_eq!(tcp_header.get_sequence(), sequence_number + last_written);               // Relative SEQ 22
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number + last_read);    // Relative ACK 27

        sequence_number += last_written; 
        acknowledgement_number += last_read;
    }
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 17 - Write ACK to tunnel.");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 18 - Send notify of data to tunnel.");
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 19 - Write data to tunnel.");
    

    {
        let len = try_read_from_fifo(&mut fifo, &mut buf[..], &mut test_event_loop, &mut test_traxi_tunnel);
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        let expected_payload = vec![
            0xff, 0xfb, 0x03, 0xff, 0xfd, 0x01, 0xff, 0xfd, 
            0x22, 0xff, 0xfd, 0x1f, 0xff, 0xfb, 0x05, 0xff, 
            0xfd, 0x21
        ];
        assert_eq!(tcp_header.payload(), &expected_payload[..]);
        assert_eq!(tcp_header.get_flags(), 0x10); // ACK.
        assert_eq!(tcp_header.get_sequence(), sequence_number);                                 // Relative SEQ 22
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number);                   // Relative ACK 27
    }

    // Tunnel should send THIRD telnet data to server.
    let mut third_telnet_data_to_server = vec![
        0x45, 0x00, 0x00, 0x43, 0x71, 0xfb, 0x40, 0x00, 0x40, 0x06, 0xf2, 0x9f, 
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8b, 0xf0, 
        0x7b, 0x56, 0x0a, 0xa1, 0x50, 0x18, 0x00, 0xe5, 0xb5, 0xca, 0x00, 0x00, 0xff, 0xfd, 0x03, 0xff,
        0xfc, 0x01, 0xff, 0xfc, 0x22, 0xff, 0xfb, 0x1f, 0xff, 0xfa, 0x1f, 0x00, 0x9e, 0x00, 0x53, 0xff,
        0xf0, 0xff, 0xfe, 0x05, 0xff, 0xfc, 0x21];
    {
        let mut tcp_header = MutableTcpPacket::new(&mut third_telnet_data_to_server[20..]).unwrap();
        tcp_header.set_acknowledgement(sequence_number);
        tcp_header.set_sequence(acknowledgement_number);
    }
    fifo.write(&third_telnet_data_to_server[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 20 - Read from tunnel.");
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 21 - Write data to server");
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 22 - Write ACK to tunnel");

    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);
        let last_read = 27;
        let last_written = 18;

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), 0x10); // ACK.
        assert_eq!(tcp_header.get_sequence(), sequence_number + last_written);               // Relative SEQ 40
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number + last_read);    // Relative ACK 54
        sequence_number += last_written; 
        acknowledgement_number += last_read;
    }
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 23 - Read from server");
    

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 24 - Read from server + Send notify to tunnel");

    // NOTE: There's some duplication in these tests, as we're not sure what order the data will
    // arrive in.

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 25 - Write data to tunnel + Send notify to tunnel");

    {
        let len = try_read_from_fifo(&mut fifo, &mut buf[..], &mut test_event_loop, &mut test_traxi_tunnel);
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), 0x10); // ACK.
        assert_eq!(tcp_header.get_sequence(), sequence_number);                                 // Relative SEQ 40
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number);                   // Relative ACK 54

        let expected_payload = vec![0xff, 0xfb, 0x01, 0xff, 0xfd, 0x06 ];
        let payload = tcp_header.payload();
        let payload_length = payload.len() as u32;

        if payload_length > 6 {
            // If the data has arrived at this point, we've run into that stupid error.
            assert!(false, "ERROR: Tunnel is behaving erroneously. You'll need to re-run the test. Sorry.");
        } else {
            assert_eq!(tcp_header.payload(), &expected_payload[..]);
        }

        sequence_number += payload_length;
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 26 - Write telnet data to FIFO");
    {
        let len = try_read_from_fifo(&mut fifo, &mut buf[..], &mut test_event_loop, &mut test_traxi_tunnel);
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), 0x10); // ACK.
        assert_eq!(tcp_header.get_sequence(), sequence_number);                              // Relative SEQ 46
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number);                // Relative ACK 54

        let payload = tcp_header.payload();
        let payload_length = payload.len() as u32;

        if payload_length > 6 {
            let expected_welcome_string = "Darwin/BSD (Kanes-MacBook-Pro-2.local)"; // DON'T include tty number!
            let welcome_string = str::from_utf8(payload).unwrap();
            assert!(welcome_string.contains(expected_welcome_string));
        }

        sequence_number += payload_length;
    }

    // Send fourth ACK to server.
    let fourth_ack_to_server = vec![
        0x45, 0x00, 0x00, 0x28, 0x56, 0x00, 0x40, 0x00, 0x40, 0x06, 0x0e, 0xb6, 
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8c, 0x01,
        0xce, 0xe6, 0xde, 0xf3, 0x50, 0x10, 0x00, 0xe5, 0xd6, 0x34, 0x00, 0x00];
    fifo.write(&fourth_ack_to_server[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 27 - Write fourth ACK to tunnel");

    // Send FIN packet to server so it closes the socket.
    let fin_packet = vec![
        0x45, 0x00, 0x00, 0x28, 0x56, 0x01, 0x40, 0x00, 0x40, 0x06, 0x0e, 0xb5,
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8c, 0x01,
        0xce, 0xe6, 0xde, 0xf3, 0x50, 0x11, 0x00, 0xe5, 0xd6, 0x34, 0x00, 0x00];
    fifo.write(&fin_packet[..]);

    acknowledgement_number += 1;

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 28 - Read FIN/ACK, then send ACK and FIN");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 29 - Queue ACK and FIN");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 30 - Read ACK from tunnel");
    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), TcpFlags::ACK);
        assert_eq!(tcp_header.get_sequence(), sequence_number);                         // Relative SEQ 111
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number);           // Relative ACK 55

        // Session should transition to FinWait (??)
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        assert_eq!(session.state, TCPState::CloseWait);
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 31 - Read FIN from tunnel");
    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), (TcpFlags::FIN | TcpFlags::ACK));
        assert_eq!(tcp_header.get_sequence(), sequence_number);                 // Relative SEQ 111
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number);   // Relative ACK 55

        // Session should transition to FinWait (??)
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        assert_eq!(session.state, TCPState::LastAck);
    }

    let mut duplicate_packet = vec![
        0x45, 0x00, 0x00, 0x28, 0x56, 0x01, 0x40, 0x00, 0x40, 0x06, 0x0e, 0xb5,
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8c, 0x02,
        0xce, 0xe6, 0xde, 0xf3, 0x50, 0x10, 0x00, 0xe5, 0xd6, 0x34, 0x00, 0x00];

    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        let mut tcp_header = MutableTcpPacket::new(&mut duplicate_packet[20..]).unwrap();
        tcp_header.set_acknowledgement(session.sequence_number);
    }

    fifo.write(&duplicate_packet[..]);
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 32 - Read duplicate ACK 😈");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 32.5 - Maybe remove session");
    // Assert session has not been removed.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token);
        assert!(session.is_some());
    }

    let mut last_ack = vec![
        0x45, 0x00, 0x00, 0x28, 0x56, 0x01, 0x40, 0x00, 0x40, 0x06, 0x0e, 0xb5, 
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8c, 0x02,
        0xce, 0xe6, 0xde, 0xf4, 0x50, 0x10, 0x00, 0xe5, 0xd6, 0x34, 0x00, 0x00];
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        let mut tcp_header = MutableTcpPacket::new(&mut last_ack[20..]).unwrap();
        tcp_header.set_acknowledgement(session.sequence_number + 1);
    }
    fifo.write(&last_ack[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 33 - Read last ACK from FIFO");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 34 - Remove session");

    // Assert session is marked as closed.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("Session not found");
        assert!(session.timeout.is_some());
    }
}

