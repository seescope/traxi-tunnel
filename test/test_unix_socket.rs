use super::*;
use mio::{EventSet, PollOpt, EventLoop, Token};
use mio::unix::{UnixListener, UnixSocket};
use std::time::Duration;
use std::io::Write;
use std::fs;

#[test]
#[ignore]
#[allow(unused_must_use)]
fn test_unix_socket() {
    init_logging();

    let ipc_path = "/Users/kanerogers/test_domain_socket"; 

    // Make sure the socket isn't in use already.
    fs::remove_file(ipc_path);

    // Build the IPC server.
    let ipc_server_result = UnixListener::bind(ipc_path);
    match ipc_server_result {
        Err(ref e) => error!("Error starting IPC server. {:?}", e), 
        _ => {}
    }
    let ipc_server = ipc_server_result.unwrap();


    // Connect to the IPC server.
    let (mut stream, _) = UnixSocket::stream().unwrap().connect(ipc_path).unwrap();

    // Write 0: indicate that screen is turned off.
    stream.write(&[0u8]);

    // Register IPC.
    let mut test_event_loop = EventLoop::new().unwrap();
    test_event_loop.register(&ipc_server, Token(1), EventSet::readable(), PollOpt::edge()).unwrap();

    // Build the tunnel.
    let test_tunnel = unsafe { build_test_fifo(true) };
    let mut test_traxi_tunnel = TraxiTunnel::new(test_tunnel, FakeEnvironment{}, ipc_server);

    // Accept the connection
    test_event_loop.run_once(&mut test_traxi_tunnel, Some(Duration::from_millis(100))).unwrap();

    // Read from the connection
    test_event_loop.run_once(&mut test_traxi_tunnel, Some(Duration::from_millis(100))).unwrap();

    // // Assert the screen is now off.
    // assert!(!test_traxi_tunnel.app_logger.screen_active);

    // Connect to the IPC server again (just as the Java client does.)
    let (mut stream, _) = UnixSocket::stream().unwrap().connect(ipc_path).unwrap();

    // Accept the connection.
    test_event_loop.run_once(&mut test_traxi_tunnel, Some(Duration::from_millis(100))).unwrap();

    // Write 1: indicate that screen is turned on.
    stream.write(&[1u8]).unwrap();

    // Read from the connection.
    test_event_loop.run_once(&mut test_traxi_tunnel, Some(Duration::from_millis(100))).unwrap();

    // // Assert the screen is now on.
    // assert!(test_traxi_tunnel.app_logger.screen_active);
}
