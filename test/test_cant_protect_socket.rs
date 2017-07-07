#[allow(unused_must_use)]
use super::*;

use std::io::prelude::*;
use mio::*;

use libc::c_int;

#[test]
#[allow(unused_must_use)]
/// When Traxi receives a connection from the device, it must connect to the *actual* remote
/// server. Sometimes this can't be done for various reasons, e.g. resource exhaustion.. In that
/// case, we drop the packet entirely (which hopefully provokes the device to attempt to connect
/// again when maybe it will have more luck). This test simulates such a failure (by failing to
/// have the environment be able to protect the socket) and checks that the session has been
/// dropped.
///
/// It is based heavily on test_rst.
fn test_rst() {
    init_logging();
    let fake_env = FakeEnvironmentCantProtect;
    let (mut test_event_loop, mut test_traxi_tunnel, mut fifo) = build_test_event_loop_with_environment(fake_env);

    let token = Token(8944366915402951162);

    let syn_to_server = vec![
        0x45, 0x00, 0x00, 0x3c, 0x32, 0xbc, 0x40, 0x00, 0x40, 0x06, 0x8e, 0xdd, 0x0a, 0x01, 0x0a, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xb1, 0xb9, 0x00, 0x17, 0x3d, 0x89, 0x27, 0x26, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0x39, 0x08, 0x79, 0x51, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
        0x10, 0xba, 0x15, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06];

    fifo.write(&syn_to_server[..]);

    test_event_loop.register(&test_traxi_tunnel.tunnel, TUNNEL, EventSet::readable(), PollOpt::edge()).unwrap();

    spin_loop(&mut test_event_loop, &mut test_traxi_tunnel, "Spin 1 - Receive ACK");
    // Sending that ACK should result in a call to connect to the remote server, which will
    // eventually wind up calling FakeEnvironmentCantProtect::protect, which will return false,
    // which should result in no session being created.
    {
        let session = test_traxi_tunnel.tcp_sessions.get(&token);
        assert!(session.is_none());
    }

    // And now there's nothing left to do!
}

/// FakeEnvironmentCantProtect is a straight copy of FakeEnvironment in test_utils, except it
/// returns *false* when attempting to protect the socket.
struct FakeEnvironmentCantProtect;
impl Environment for FakeEnvironmentCantProtect {
    fn protect(&self, _: c_int) -> bool {
        false
    }

    fn get_package_name(&mut self, _: usize) -> String {
        "".to_string()
    }

    fn report_error(&self, _: &str) {}

    fn get_uuid(&mut self, _: &Ipv4Addr) -> Option<String> { None }

    fn get_file_path(&self) -> String { "./".to_string() }
}
