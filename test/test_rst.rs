#[allow(unused_must_use)]
use super::*;

use std::io::prelude::*;
use mio::*;
use pnet::packet::tcp::{TcpPacket, TcpFlags};

#[test]
#[allow(unused_must_use)]
/// When we receive a reset (RST) packet, it is an indication from the client that we should end
/// the current session *immediately*. See [The TCP/IP
/// Guide](http://www.tcpipguide.com/free/t_TCPConnectionManagementandProblemHandlingtheConnec.htm)
/// for a more detailed explanation of how TCP RST works, and why/when it should be used, and
/// [RF793](https://www.ietf.org/rfc/rfc793.txt) pages 33-34 for a *very* detailed explanation.
fn test_rst() {
    init_logging();
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();

    let token = Token(8944366915402951162);
    let sequence_number;
    let acknowledgement_number;
    let mut buf = [0u8; 2048];

    let syn_to_server = vec![
        0x45, 0x00, 0x00, 0x3c, 0x32, 0xbc, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xdd, 0x0a, 0x01, 0x0a, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x26, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0x39, 0x08, 0x79, 0x51, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
        0x10, 0xba, 0x15, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06];

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
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("No session found");
        sequence_number = session.sequence_number; // Use our own SEQ.
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 2 - Receive data from server");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 3 - Write SYN/ACK to Tunnel");
    
    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        // Assert that we received a valid SYN/ACK.
        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), TcpFlags::SYN | TcpFlags::ACK);
        assert_eq!(tcp_header.get_sequence(), sequence_number); // Should be same. 
        assert_eq!(tcp_header.get_acknowledgement(), acknowledgement_number + 1); // Should be incremented.
    }

    let ack = vec![
        0x45, 0x00, 0x00, 0x28, 0x32, 0xbd, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xf0, 0x0a, 0x01, 0x0a, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x27, 0xb4, 0x89, 0x32, 0x4c,
        0x50, 0x10, 0x00, 0xe5, 0x79, 0x3d, 0x00, 0x00];
    fifo.write(&ack[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 4 - Read ACK");

    let rst = vec![
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x13, 0x4f, 0x0a, 0x01, 0x0a, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0xa6, 0x4c, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x04, 0x00, 0x00, 0x9c, 0xb1, 0x00, 0x00];
    fifo.write(&rst[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 5 - Read RST");

    fifo.write(&rst[..]);
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 6 - Read another RST");

    // Assert that the session is now removed.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token);
        assert!(session.is_none());
    }
}
