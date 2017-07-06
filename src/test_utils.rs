use rand;

use std::collections::VecDeque;
use std::io::prelude::*;
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use std::net::Ipv4Addr;

use libc::c_int;

use mio::{EventLoop, Io, Token, EventSet};
use mio::unix::UnixListener;
use mio::tcp::TcpStream;

use tunnel::{TraxiTunnel, Environment};
use tcp::session::{TCPSession, TCPState};
use tcp::retransmission_timer::RetransmissionTimer;
use app_logger::AppLogger;


#[cfg(not(target_os="android"))]
use libc::mkfifo;

pub fn test_session() -> TCPSession {
    let test_source_ip = Ipv4Addr::new(192,168,1,112);
    let test_destination_ip = Ipv4Addr::new(192,168,1,184);

    let test_source_port:u16 = 41343;
    let test_destination_port:u16 = 23;

    let remote_addr = "127.0.0.1:80".parse().unwrap();
    let test_tcp_stream = TcpStream::connect(&remote_addr).unwrap();

    TCPSession {
        source_ip: test_source_ip,
        destination_ip: test_destination_ip,
        source_port: test_source_port,
        destination_port: test_destination_port,
        socket: Some(test_tcp_stream),
        state: TCPState::Closed,
        acknowledgement_number: 5000,
        sequence_number: 0,
        unacknowledged: 0,
        congestion_window: 9999,
        receiver_window: 1234,
        mut_buf: None,
        interest: EventSet::none(),
        write_queue: vec![],
        read_queue: VecDeque::new(),
        token: Token(5),
        timeout: None,
        mss: 1337,
        retransmission_queue: VecDeque::new(),
        duplicate_ack_count: 0,
        window_scaling_factor: None,
        slow_start_threshold: 9999,
        entered_fast_retransmit: None,
        retransmission_timer: RetransmissionTimer::new(),
        last_acknowledgement: 0,
        app_logger: AppLogger::new("./".to_string(), test_destination_ip),
    }
}

pub const TUNNEL:Token = Token(0);

/// Run the Event Loop once to respond to activity on the watched file descriptors. Print out a
/// nice message to tell everyone what's going on.
pub fn spin_loop<T: Environment>(test_event_loop: &mut EventLoop<TraxiTunnel<T>>, mut test_traxi_tunnel: &mut TraxiTunnel<T>, message: &str) {
    use ansi_term::Colour::Green;
    debug!("{}", Green.paint(message));
    test_event_loop.run_once(test_traxi_tunnel, Some(Duration::from_millis(100))).unwrap();
}

/// In production, we call out to the JVM to call #protect on our sockets so that the Android VPN
/// won't loop our outbound requests. In our tests, we have no such restriction, and so we can
/// simply return "true".
pub struct FakeEnvironment;
impl Environment for FakeEnvironment {
    fn protect(&self, _: c_int) -> bool {
        true
    }

    fn get_package_name(&mut self, _: usize) -> String {
        "".to_string()
    }

    fn report_error(&self, _: &str) {}

    fn get_uuid(&mut self, _: &Ipv4Addr) -> Option<String> { None }

    fn get_file_path(&self) -> String { "./".to_string() }
}

/// In order to replicate the VPN tunnel, our tests make use of a FIFO, an in-memory "pipe" that
/// allows us to read and write from each end. For a detailed explanation on Named Pipes and how
/// they work, take a look at [the Wikipedia article](https://en.wikipedia.org/wiki/Named_pipe)
#[cfg(not(target_os="android"))]
pub unsafe fn build_test_fifo(nonblocking: bool) -> Io {
    use std::ffi::CString;
    use std::io::Error;
    use libc::{open, O_RDWR, O_NONBLOCK, O_RDONLY};

    let fifo_number = rand::random::<u32>();
    let fifo_path_string = format!("/tmp/test_fifo_{}", fifo_number);
    let fifo_path = CString::new(fifo_path_string).unwrap();
    let fifo_path_ptr = fifo_path.as_ptr();
    mkfifo(fifo_path_ptr, 0o777);

    let flags = if nonblocking { O_RDWR | O_NONBLOCK } else { O_RDONLY };
    let fd = open(fifo_path_ptr, flags);

    if fd == -1 {
        info!("Error opening FIFO! {:?}", Error::last_os_error())
    }

    Io::from_raw_fd(fd)
}

#[cfg(target_os="android")]
pub unsafe fn build_test_fifo(_: bool) -> Io {
    Io::from_raw_fd(1)
}

/// Try reading from the FIFO pipe. Retry on failure.
pub fn try_read_from_fifo<T: Environment>(fifo: &mut Io, buf: &mut [u8], test_event_loop: &mut EventLoop<TraxiTunnel<T>>, test_traxi_tunnel: &mut TraxiTunnel<T>) -> usize {
    match fifo.read(buf) {
        Ok(len) => len,
        Err(_)  => {
            error!("FIFO: Read failed. Spinning again.");
            test_event_loop.run_once(test_traxi_tunnel, None).unwrap();
            error!("FIFO: Spun. Attempting read again.");
            // TODO: Perhaps try again?
            fifo.read(buf).unwrap()
        }
    }
}

pub fn build_test_event_loop<T: Environment>() -> ((EventLoop<TraxiTunnel<T>>, TraxiTunnel<FakeEnvironment>, Io)) {
    let test_tunnel = unsafe { build_test_fifo(true) };
    let fifo_fd = test_tunnel.as_raw_fd();
    let fifo = Io::from_raw_fd(fifo_fd);

    let socket_number = rand::random::<u32>();
    let ipc_path = format!("/tmp/ipc_{}", socket_number);
    let ipc_server = UnixListener::bind(&ipc_path).unwrap();

    let fake_environment = FakeEnvironment;
    let traxi_tunnel = TraxiTunnel::new(test_tunnel, fake_environment, ipc_server);
    let event_loop = EventLoop::new().unwrap();

    (event_loop, traxi_tunnel, fifo)
}

#[cfg(target_os="android")]
pub fn init_logging() {
}

#[cfg(not(target_os="android"))]
pub fn init_logging() {
    extern crate log4rs;
    drop(log4rs::init_file("config/test.yaml", Default::default()));
}
