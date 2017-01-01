use super::*;
use mio::*;
use traxi::tcp::session::TCPState;
use pnet::packet::tcp::MutableTcpPacket;
use std::io::Write;

#[test]
#[allow(unused_must_use)]
#[allow(unused_variables)]
fn test_adjust_window_size() {
    init_logging();

    let token = Token(8944366915402951162);
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    // Create a fake session and insert it into the map.
    let mut session = test_session();
    session.token = token;
    session.state = TCPState::Established;
    test_traxi_tunnel.tcp_sessions.insert(token, session);

    let mut ack = vec![
        0x45, 0x00, 0x00, 0x28, 0x32, 0xbd, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xf0, 0x0a, 0x01, 0x0a, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x27, 0xb4, 0x89, 0x32, 0x4c,
        0x50, 0x10, 0x00, 0xe5, 0x79, 0x3d, 0x00, 0x00];
    {
        let mut tcp_header = MutableTcpPacket::new(&mut ack[20..]).unwrap();
        tcp_header.set_window(10);
    }

    fifo.write(&ack[..]);

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Process ACK");

    let session = test_traxi_tunnel.tcp_sessions.get(&token).expect("No session found");
    assert_eq!(session.receiver_window, 10);
}
