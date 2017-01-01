use super::*;

use mio::*;
use std::io::prelude::*;
use traxi::packet_helper::*;
use pnet::packet::tcp::TcpPacket;
use traxi::tcp::session::TCPState;

#[test]
#[allow(unused_must_use)]
/// In an ideal world, a SYN packet will be the first packet we receive for a given token (port/IP
/// combination). However, because of the uncertain nature of networks, we might occasionally
/// recieve packets out-of-order, or the client may think it's in a different state to us. If we do
/// receive a packet for an unestablished session, we should send back an RST to tell the client to
/// start again from scratch.
///
/// The exception to this rule is that clients will ocassionally send RSTs to "re-establish" a session. 
/// In this case, we should delete the session if it exists, and simply drop the packet on the
/// floor.
fn test_send_rst_if_no_session() {
    init_logging();
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    let token = Token(15452203518671342293);

    let mut buf = [0u8; 2048];
    let ack = vec![
        0x45, 0x00, 0x00, 0x28, 0x32, 0xbd, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xf0, 0x0a, 0x01, 0x0a, 0x01,
        0xdc, 0xf4, 0x88, 0x2c, 0xb1, 0xb9, 0x01, 0xbb, 0x3d, 0x89, 0x27, 0x27, 0xb4, 0x89, 0x32, 0x4c,
        0x50, 0x10, 0x00, 0xe5, 0x79, 0x3d, 0x00, 0x00];

    fifo.write(&ack[..]);

    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 1 - Receive ACK");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 2 - Write RST");
    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    {
        let len = fifo.read(&mut buf[..]).unwrap();
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        // Assert that we received a valid RST.
        let packet_type = get_packet_type(&buf[..len]).unwrap();

        // Assert we cleaned up the session.
        let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("No session found!");
        assert!(session.state == TCPState::Closed);

        let tcp_header = TcpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(tcp_header.get_sequence(), 0xb489324c); // Acknowledgement Number of received packet.
        assert_eq!(tcp_header.get_acknowledgement(), 0);   // Should be zero.

        assert_eq!(packet_type, PacketType::TCP(TCP::RST));
    }
}
