#[allow(unused_must_use)]

use super::*;

use std::io::prelude::*;
use std::str;
use traxi::tcp::session::*;
use mio::*;
use pnet::packet::tcp::{TcpPacket, TcpFlags};
use pnet::packet::Packet;

#[test]
#[allow(unused_must_use)]
/// TCP has a built in mechanism to detect packet failure known as TCP retransmission. Essentially,
/// if a TCP does not receive an ACK to a transmission, it will retransmit the packet after a
/// intederminate period of time.
///
/// In such cases, it's important the receiver end (namely, traxi), discards these duplicate
/// transmissions. Failure to do so would mean a duplication of data, and generally awful
/// circumstances.
pub fn test_retransmissions() {
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

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 1 - Receive SYN");
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
        assert_eq!(tcp_header.get_flags(), TcpFlags::SYN | TcpFlags::ACK); // 0x12 == SYN/ACK.
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

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 6 - Send data from read_queue to notify");
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 7 - Write data from remote back to tunnel");

    {
        let len = fifo.read(&mut buf[..]).expect("Unable to read first telnet data");
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
    let telnet_data_to_server = vec![
        0x45, 0x00, 0x00, 0x37, 0x71, 0xf9, 0x40, 0x00, 0x40, 0x06, 0xf2, 0xad, 
        0x0a, 0x01, 0x0a, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x1f, 0x00, 0x17, 0xfa, 0xab, 0x8b, 0xcc, 
        0x45, 0x56, 0xcd, 0xc8, 0x50, 0x18, 0x00, 0xe5, 0x9b, 0xe4, 0x00, 0x00, 0xff, 0xfb, 0x18, 0xff, 
        0xfc, 0x20, 0xff, 0xfc, 0x23, 0xff, 0xfc, 0x27, 0xff, 0xfc, 0x24];

    fifo.write(&telnet_data_to_server[..]); 

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 8 - Read data from FIFO.");
    

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 9 - Send telnet data to server");
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 10 - Send ACK to tunnel + Read from server");

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


    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 12 - Write data to tunnel.");

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

    // Intentionally retransmit last packet.
    fifo.write(&telnet_data_to_server[..]); 
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 14 - RETRANSMIT!!");

    // Assert we did not process this packet.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        assert_eq!(session.acknowledgement_number, 0xfaab8bdb);
    }

}
