use super::*;
use std::str;
use std::io::prelude::*;
use std::net;
use mio::*;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[test]
#[allow(unused_must_use)]
fn test_udp() {
    init_logging();
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    let mut buf = [0u8; 2048];

    let localhost = net::Ipv4Addr::new(127, 0, 0, 1);
    let listen_addr = net::SocketAddrV4::new(localhost, 1234);
    let udp_socket = net::UdpSocket::bind(listen_addr).unwrap();

    let message = vec![
    0x45, 0x00, 0x00, 0x23, 0xdd, 0xb1, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xf5, 0xe2, 0x04, 0xd2, 0x00, 0x0f, 0xfe, 0x22,
    0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x0a];

    fifo.write(&message[..]);

    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 1 - Receive message");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 2 - Write to socket");


    {
        let (length, from_address) = udp_socket.recv_from(&mut buf).unwrap();
        let message = str::from_utf8(&buf[..length]).unwrap();

        assert_eq!(message, "client\n");

        let reply = "server".as_bytes();
        udp_socket.send_to(&reply[..], &from_address).unwrap();
    }


    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 3 - Receive from socket");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 4 - Queue message");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 5 - Write to tunnel");

    {
        let expected_message = "server".as_bytes();
        let len = try_read_from_fifo(&mut fifo, &mut buf[..], &mut test_event_loop, &mut test_traxi_tunnel);
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let udp_header = UdpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(udp_header.payload(), &expected_message[..]);
    }
}

/// This test performs a full DNS query to Google DNS (8.8.8.8). Ignored because it's error prone /
/// slow.
#[test]
#[ignore]
#[allow(unused_must_use)]
fn test_dns_session() {
    init_logging();
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    let mut buf = [0u8; 2048];

    let dns_request = vec![
        0x45, 0x00,
        0x00, 0x37, 0x80, 0x79, 0x00, 0x00, 0x40, 0x11, 0x27, 0x9c, 0xc0, 0xa8, 0x01, 0xe9, 0x08, 0x08,
        0x08, 0x08, 0xd8, 0x35, 0x00, 0x35, 0x00, 0x23, 0xd9, 0xc3, 0x32, 0xc1, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x63, 0x69, 0x73, 0x63, 0x6f, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01];

    fifo.write(&dns_request[..]);

    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 1 - Receive message");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 2 - Write to socket");
    
    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 3 - Receive from socket");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 4 - Queue message");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 5 - Write to tunnel");
    
    {
        let expected_response = vec![
            0x32, 0xc1, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 
            0x00, 0x00, 0x00, 0x00, 0x05, 0x63, 0x69, 0x73, 
            0x63, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 
            0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 
            0x01, 0x00, 0x00];

        let len = try_read_from_fifo(&mut fifo, &mut buf[..], &mut test_event_loop, &mut test_traxi_tunnel);
        debug!("FIFO: Read {} bytes: {:?}", len, &buf[..len]);

        let udp_header = UdpPacket::new(&buf[20..len]).unwrap();
        assert_eq!(&udp_header.payload()[..35], &expected_response[..]);
    }
}

/// This test is kind of annoying, as there is no safe way of pausing the EventLoop to check its
/// state. Instead, run the test and make sure that "REMOVING SESSION", followed by "Successfully
/// removed session" appears in the logs.
#[test]
#[ignore]
#[allow(unused_must_use)]
fn test_timeout() {
    init_logging();
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop();
    let token = Token(12241921793775994035);

    let message = vec![
    0x45, 0x00, 0x00, 0x23, 0xdd, 0xb1, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xf5, 0xe2, 0x04, 0xd2, 0x00, 0x0f, 0xfe, 0x22,
    0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x0a];

    fifo.write(&message[..]);

    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 1 - Receive message");

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 2 - Write to socket");

    info!("Running event loop.");

    test_event_loop.run(&mut test_traxi_tunnel).unwrap();

    info!("Woke up from event loop.");

    let session = test_traxi_tunnel.udp_sessions.get(&token);
    assert!(session.is_none());
}
