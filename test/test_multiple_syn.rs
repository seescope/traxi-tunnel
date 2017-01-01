#[allow(unused_must_use)]
use super::*;

use std::io::prelude::*;
use mio::*;
use pnet::packet::tcp::{TcpPacket, TcpFlags};

#[test]
#[allow(unused_must_use)]
/// When using traxi in remote VPN mode, there will certainly be latency between the client and the
/// VPN server. In this case, there may be situations where the client has sent a SYN, doesn't
/// receive an ACK for some seconds, and so sends several more SYN packets. In such cases, we
/// should simply ignore subsequent SYNs for a session that is already in our map, rather than
/// creating a new session each time, and thus sending duplicate, erroneous, ACKs.
fn test_multiple_syn() {
    init_logging();
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();

    let token = Token(8944366915402951162);
    let session_string;
    let mut buf = [0u8; 2048];

    let syn_to_server = vec![
        0x45, 0x00, 0x00, 0x3c, 0x32, 0xbc, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xdd, 0x0a, 0x01, 0x0a, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x26, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0x39, 0x08, 0x79, 0x51, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
        0x10, 0xba, 0x15, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06];

    fifo.write(&syn_to_server[..]);

    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 1 - Receive SYN");
    {
        // Since we can't get derive PartialEq on the only unique field (session.socket), let's
        // compare by its string representation instead. :- )
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        session_string = format!("{:?}", session.socket);
    }

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 2 - Receive data from server");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 3 - Write SYN/ACK to Tunnel");
    
    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        // Assert that we received a valid SYN/ACK.
        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_flags(), TcpFlags::SYN | TcpFlags::ACK);
    }

    // Write a SYN again.
    fifo.write(&syn_to_server[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 4 - Receive second SYN");

    {
        // Assert that this is the SAME socket (eg. we have not created a new session).
        let session = test_traxi_tunnel.tcp_sessions.get(&token).unwrap();
        assert_eq!(format!("{:?}", session.socket), session_string);
    }
}

