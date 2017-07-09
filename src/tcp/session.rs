use pnet::packet::Packet;
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::tcp::{TcpPacket, TcpOptionNumbers};

use mio::tcp::TcpStream;
use mio::{Timeout, Token, EventLoop, EventSet, PollOpt, TryRead, Handler};

use std::io::{Write, Read, Result, Cursor};
use std::fs::File;
use std::os::unix::io::{AsRawFd};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;
use std::cmp;
use std::collections::VecDeque;

use bytes::{ByteBuf, MutByteBuf};
use byteorder::{BigEndian, ReadBytesExt};

use net2::TcpBuilder;

use rand::random;

use tunnel::{TraxiMessage, Environment, get_socket_token};
use packet_helper::{TCP, PacketType};
use super::retransmission_timer::RetransmissionTimer;
use super::segment::TCPSegment;
use app_logger::AppLogger;
use Result as TraxiTunnelResult;
use TraxiError;


#[derive(Debug, PartialEq)]
pub enum TCPState {
    Closed,
    SynSent,
    Established,
    CloseWait,
    FinWait1,
    FinWait2,
    TimeWait,
    LastAck,
}

#[derive(Debug)]
pub struct TCPSession {
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub state: TCPState,
    pub socket: Option<TcpStream>,
    pub acknowledgement_number: u32,
    pub sequence_number: u32,
    pub unacknowledged: u32, // SND.UNA
    pub congestion_window: u32, // cwnd
    pub receiver_window: u32, // RCV.WIN
    pub token: Token,
    pub interest: EventSet,
    pub mut_buf: Option<MutByteBuf>,
    pub read_queue: VecDeque<Vec<u8>>,
    pub write_queue: Vec<Vec<u8>>,
    pub timeout: Option<Timeout>,
    pub mss: u16,
    pub retransmission_queue: VecDeque<TCPSegment>,
    pub duplicate_ack_count: u8,
    pub window_scaling_factor: Option<u16>,
    pub slow_start_threshold: u32,
    pub entered_fast_retransmit: Option<u32>, // NewReno recover
    pub retransmission_timer: RetransmissionTimer,
    pub last_acknowledgement: u32,
    pub app_logger: AppLogger,
}

impl TCPSession {
    pub fn new<T: Environment>(packet: &[u8], environment: &T) -> TraxiTunnelResult<TCPSession> {
        let ip_header = Ipv4Packet::new(&packet[..]).unwrap();
        let tcp_header = TcpPacket::new(&ip_header.payload()[..]).unwrap();

        let source_ip = ip_header.get_source();
        let destination_ip = ip_header.get_destination();
        let source_port = tcp_header.get_source();
        let destination_port = tcp_header.get_destination();
        let acknowledgement_number = tcp_header.get_sequence(); // Use the remote's SEQ for our ACK.
        let sequence_number = random::<u32>();                  // We determine our own SEQ.

        let magic_ip = Ipv4Addr::new(123, 123, 123, 123);

        let socket = if destination_ip == magic_ip {
            None
        } else {
            let socket_addr = SocketAddr::new(IpAddr::V4(destination_ip), destination_port);
            match create_socket(&socket_addr, environment) {
                Ok(s) => Some(s),
                Err(e) => return Err(e),
            }
        };

        let mss = tcp_header.get_options_iter()
            .find(|option| option.get_number() == TcpOptionNumbers::MSS)
            .and_then(|mss_field| {
                let mut reader = Cursor::new(mss_field.payload());
                reader.read_u16::<BigEndian>().ok()
            }).unwrap_or(536); // As per RFC1122;

        let initial_window_size = mss as u32 * 3; // As per RFC6898

        let window = tcp_header.get_window() as u32;
        let window_scaling_factor = get_window_scaling_factor(&tcp_header);
        let receiver_window = if let Some(window_scaling_factor) = window_scaling_factor {
            window << window_scaling_factor
        } else {
            window
        };

        let app_logger = AppLogger::new(environment.get_file_path(), destination_ip);

        Ok(TCPSession {
            source_ip: source_ip,
            destination_ip: destination_ip,
            source_port: source_port,
            destination_port: destination_port,
            state: TCPState::Closed,
            socket: socket,
            acknowledgement_number: acknowledgement_number,
            sequence_number: sequence_number,
            unacknowledged: sequence_number,
            congestion_window: initial_window_size,
            receiver_window: receiver_window,
            token: get_socket_token(packet),
            interest: EventSet::readable(),
            mut_buf: Some(ByteBuf::mut_with_capacity(8192)),
            read_queue: VecDeque::with_capacity(10),
            write_queue: vec![],
            timeout: None,
            mss: mss,
            retransmission_queue: VecDeque::with_capacity(10),
            duplicate_ack_count: 0,
            window_scaling_factor: window_scaling_factor,
            slow_start_threshold: initial_window_size,
            entered_fast_retransmit: None,
            retransmission_timer: RetransmissionTimer::new(),
            last_acknowledgement: 0,
            app_logger: app_logger,
        })
    }

    pub fn writable<H: Handler<Message = TraxiMessage, Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) -> Result<()> {
        while self.write_queue.len() > 0 {
            let packet = self.write_queue.remove(0);
            let mut socket = self.socket.take().unwrap();
            match socket.write(&packet[..]) {
                Ok(len) => {
                    debug!("SESSION WRITE {}| WROTE {}", self.token.as_usize(), len);

                    self.interest.insert(EventSet::readable());
                    self.interest.remove(EventSet::writable());
                }
                Err(e) => {
                    error!("SESSION WRITE {}| Error writing to tunnel {:?}. Doing nothing.", self.token.as_usize(), e);
                }
            }

            self.socket = Some(socket);
        }

        self.reregister(event_loop)
    }

    pub fn readable<H: Handler<Message=TraxiMessage, Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) -> Result<()> {
        // Prepare a buffer to read the data.
        let mut buf = self.mut_buf.take().unwrap_or(ByteBuf::mut_with_capacity(8192));
        buf.clear();

        // By default, we are interested in reads.
        self.interest = EventSet::readable();

        let mut socket = self.socket.take().expect("COULDN'T GET TO SOCKET");
        match socket.try_read_buf(&mut buf) {
            Ok(None) => {
                debug!("SESSION {}| Got Ok(None). Ignoring.", self.token.as_usize());
            }
            Ok(Some(len)) if len > 0 => {
                self.app_logger.log_response(len, &event_loop.channel());

                let packet = &buf.bytes()[..len];
                debug!("SESSION READ {}| Read {} bytes.", self.token.as_usize(), len);

                match self.state {
                    TCPState::SynSent       => self.queue_data(packet),
                    TCPState::Established   => self.send_data(packet, event_loop),
                    ref invalid_state       => error!("SESSION {}| Got readable in {:?}! Doing nothing.", self.token.as_usize(), invalid_state),
                }

            },
            Ok(Some(_)) => {
                debug!("SESSION READ {}| Read 0 bytes. Handling HUP.", self.token.as_usize());
                self.handle_hup(event_loop);

                // As the socket is now essentially closed, this is the only case where we don't want to listen for reads.
                self.interest = EventSet::none();

                // Don't use self.reregister here, it can't handle the hup case (yet).
                let result = event_loop.reregister(&socket, self.token, self.interest, PollOpt::edge());
                self.socket = Some(socket);
                return result;
            }
            Err(e) => {
                error!("SESSION READ {}| Error reading from socket: {:?}. Closing session and sending RST", self.token.as_usize(), e);
                self.close_session(event_loop);
            }
        };

        self.mut_buf = Some(buf);
        self.socket = Some(socket);
        self.reregister(event_loop)
    }

    pub fn send_ack<H: Handler<Message=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>, sequence_number: u32) {
        debug!("SESSION SEND_ACK {}| Sending ACK with SEQ {}", self.token.as_usize(), sequence_number);
        let sender = event_loop.channel();
        let message = TraxiMessage::QueuePacket(PacketType::TCP(TCP::ACK(sequence_number)), self.token);
        sender.send(message).unwrap(); // TODO Handle error?
    }

    pub fn send_syn_ack<H: Handler<Message = TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) {
        let sender = event_loop.channel();
        self.acknowledgement_number += 1;

        debug!("SESSION: Sent SYN/ACK. SEQ {}, ACK {}", self.sequence_number, self.acknowledgement_number);

        let message = TraxiMessage::QueuePacket(PacketType::TCP(TCP::SYNACK), self.token);
        sender.send(message).expect("Couldn't send SYN/ACK"); // TODO Handle error?
    }

    pub fn send_data<H: Handler<Message=TraxiMessage, Timeout=TraxiMessage>>(&mut self, data: &[u8], event_loop: &mut EventLoop<H>) {
        for chunk in data.chunks(self.mss as usize) {
            let sequence_number = self.sequence_number;
            if self.is_within_congestion_window(sequence_number) && self.read_queue.len() == 0 {
                let data = chunk.to_vec();
                self.send_data_segment(data, event_loop);
            } else {
                debug!("SEND_DATA {}: Send window is full. Adding packet to read queue.", self.token.as_usize());

                self.read_queue.push_back(chunk.to_vec());
            }
        }
    }

    pub fn send_fin_ack<H: Handler<Message = TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) {
        let sender = event_loop.channel();
        let message = TraxiMessage::QueuePacket(PacketType::TCP(TCP::FINACK), self.token);

        debug!("SEND_FIN_ACK: Sending packet to queue: {:?}", message);

        sender.send(message).unwrap(); // TODO Handle error?
    }

    pub fn queue_data(&mut self, data: &[u8]) {
        // Since we know that the sequence number will be incremented by 1 when we move to
        // Established, queue this packet with SEQ + 1.
        let packet_sequence_number = self.sequence_number + 1;

        debug!("SESSION QUEUE_DATA {}| QUEUING SEG {} | SEQ {}", self.token.as_usize(), packet_sequence_number, self.sequence_number);

        self.read_queue.push_back(data.to_vec());
    }

    pub fn close_session<H: Handler<Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) {
        debug!("CLOSE_SESSION {}| Setting timeout for session.", self.token.as_usize());

        // Set a timeout to close the session in 30 seconds.
        let tcp_timeout = Duration::from_millis(30000);
        self.timeout = event_loop.timeout(TraxiMessage::CloseTCPSession(self.token.clone()), tcp_timeout).ok();

        // Cancel any outstanding retransmissions.
        self.retransmission_timer.stop_timer(event_loop, self.token);
    }

    pub fn handle_hup<H: Handler<Message = TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) {
        if self.state == TCPState::Established {
            if self.read_queue.len() > 0 {
                debug!("SESSION E {}| Received HUP, but read queue still has {} items in it",
                       self.token.as_usize(), self.read_queue.len());
                return;
            }

            if self.unacknowledged != self.sequence_number {
                debug!("SESSION E {}| Received HUP, but there is still oustanding data: UNA {} | SEQ {}",
                       self.token.as_usize(), self.unacknowledged, self.sequence_number);
                return;
            }

            debug!("SESSION E {}| Received HUP. Moving to FINWAIT1", self.token.as_usize());

            self.state = TCPState::FinWait1;
            self.send_fin_ack(event_loop);
        } else {
            debug!("SESSION {:?} {}| Received HUP, but session is already shutting down. Doing nothing.", self.state, self.token.as_usize());
        }
    }

	/// [RFC 5681:2](https://tools.ietf.org/html/rfc5681#section-2)
	/// At any given time, a TCP MUST NOT send data with a sequence number higher than the sum of the highest acknowledged sequence number and
    /// the minimum of cwnd and rwnd.
    pub fn is_within_congestion_window(&self, packet_sequence_number: u32) -> bool {
        // RFC 5681: [During Fast Retransmit] when previously unsent data is available [..] a TCP SHOULD send 1*SMSS bytes of previously unsent data.
        let edge_of_window = if let Some(recover) = self.entered_fast_retransmit {
            (recover + self.mss as u32) + 1
        } else {
            self.unacknowledged + cmp::min(self.congestion_window, self.receiver_window)
        };

        trace!("IS_WITHIN_CONGESTION_WINDOW {}| SEG.SEQ {} | UNA {} | EDGE {} | SEQ {}",
               self.token.as_usize(), packet_sequence_number, self.unacknowledged, edge_of_window, self.sequence_number);

        packet_sequence_number < edge_of_window
    }

    pub fn update_window_size(&mut self, packet: &TcpPacket) {
        let packet_window_size = packet.get_window() as u32;
        if let Some(window_scaling_factor) = get_window_scaling_factor(packet) {
            self.window_scaling_factor = Some(window_scaling_factor);
        }

        if let Some(window_scaling_factor) = self.window_scaling_factor {
            let window_size = packet_window_size << window_scaling_factor;
            self.receiver_window = window_size;
            debug!("UPDATE_WINDOW_SIZE {}| SEG.WND {} | WSF {} | RCV.WND {}",
                   self.token.as_usize(), packet_window_size, window_scaling_factor, self.receiver_window);
        } else {
            self.receiver_window = packet_window_size;
        }
    }

    pub fn flush_read_queue<H: Handler<Message = TraxiMessage, Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) {
        debug!("FLUSH_READ_QUEUE {}| Queue length: {:?}", self.token.as_usize(), self.read_queue.len());
        let mut found_index = None;
        let initial_queue_size = self.read_queue.len();

        // This logic is quite tricky.
        //
        // To calculate the relative sequence number of each segment in the queue, we need to first take note
        // of the *current* sequence number.
        // eg: loop_sequence_number = 5
        let mut loop_sequence_number = self.sequence_number;

        for (index, data) in self.read_queue.iter().enumerate() {
            // Then here we'll take the outer sequence number to use later.
            // eg: sequence_number = 5
            let sequence_number = loop_sequence_number;

            // And increment the outer sequence number for the next iteration to use.
            // eg: len = 5; loop_sequence_number = 5 + 5 == 10
            loop_sequence_number += data.len() as u32;

            // Find the first entry that is NOT within the congestion_window.
            // eg: found_index = 5
            if !self.is_within_congestion_window(sequence_number) {
                found_index = Some(index);
                break;
            }
        }

        if let Some(found_index) = found_index {
            // There are items in the read_queue that are NOT within the congestion window.
            //
            // Work from the start of the queue up until the item that is NOT within the
            // congestion_window. eg. items 0 to 5.
            for _ in 0..found_index {
                // Remove the segment from the queue and send it to the client.

                if let Some(data) = self.read_queue.pop_front() {
                    self.send_data_segment(data, event_loop);
                }
            }
        } else {
            // All items in the read_queue are within the congestion window - safe to flush the
            // entire queue.
            while let Some(data) = self.read_queue.pop_front() {
                self.send_data_segment(data, event_loop);
            }
        }

        // If we've now reduced the size of the queue, attempt to read again.
        if initial_queue_size >= 10 && self.read_queue.len() < 10 {
            debug!("FLUSH_READ_QUEUE {}| Space available in read queue. Attempting to read from socket again: {:?}",
                   self.token.as_usize(), self.read_queue.len());
            drop(self.readable(event_loop));
        }
    }

    pub fn update_unacknowledged<H: Handler<Timeout=TraxiMessage>>(&mut self, acknowledgement_number: u32, event_loop: &mut EventLoop<H>) {
        if self.unacknowledged < acknowledgement_number {
            self.unacknowledged = acknowledgement_number;
        }

        if self.unacknowledged == self.sequence_number {
            debug!("UPDATE_SEQUENCE_NUMBER {}| All packets acknowledged!", self.token.as_usize());
            self.retransmission_timer.stop_timer(event_loop, self.token);
        }   else {
            debug!("UPDATE_SEQUENCE_NUMBER {}| Outstanding packets still remaining!", self.token.as_usize());
            self.retransmission_timer.restart_timer(event_loop, self.token);
        }
    }

    /// [RFC 5681:2](https://tools.ietf.org/html/rfc5681#section-2)
    /// An acknowledgment is considered a "duplicate" [..] when [..] the acknowledgment number is
    /// equal to the greatest acknowledgment received on the given connection.
    pub fn check_duplicate_ack(&mut self, acknowledgement_number: u32) {
        if self.last_acknowledgement == acknowledgement_number {
            self.duplicate_ack_count += 1;
            debug!("DUPLICATE ACK DETECTED! {}| LAST_ACK: {} - ACK: {} - DUP_ACK : {}",
                   self.token.as_usize(), self.unacknowledged, acknowledgement_number, self.duplicate_ack_count);

            // If we have received more than 3 duplicate ACKs, now enter Fast Retransmit.
            if self.should_enter_fast_retransmit() { self.enter_fast_retransmit() }
        } else {
            // Happy case! This is a non-duplicate ACK.

            if self.entered_fast_retransmit.is_some() {
                self.enter_fast_recovery(acknowledgement_number);
            }

            self.entered_fast_retransmit = None;
            self.duplicate_ack_count = 0;
        }

        // Take note of this acknowledgement_number and record it as last_acknowledgement.
        self.last_acknowledgement = acknowledgement_number;
    }

    pub fn update_retransmission_queue(&mut self, packet_acknowledgement: u32) {
        let initial_size = self.retransmission_queue.len();
        self.retransmission_queue.retain(|ref segment| {
            !is_fully_acknowledged(packet_acknowledgement, segment.sequence_number, segment.len())
        });

        let new_size = self.retransmission_queue.len();
        let removed = initial_size - new_size;

        if removed > 0 {
            debug!("UPDATE_RETRANSMISSION_QUEUE {}| Removed {} items. retransmission_queue length is now {}",
                   self.token.as_usize(), removed, new_size);
        }
    }

    /// [RFC 5681 3.1](https://tools.ietf.org/html/rfc5681#section-3.1)
    /// The slow start and congestion avoidance algorithms MUST be used by a TCP sender to control
    /// the amount of outstanding data being injected into the network.
    pub fn expand_congestion_window(&mut self) {
        // RFC 5681: TCP sender MUST NOT change cwnd to reflect [..] two [duplicate] segments
        if self.duplicate_ack_count > 0 {
            return;
        }

        if self.should_use_slow_start() {
            // RFC 5681: During slow start, a TCP increments cwnd by at most SMSS bytes for each
            // ACK received that cumulatively acknowledges new data.
            self.congestion_window += self.mss as u32;
            debug!("EXPAND_CONGESTION_WINDOW {}| Using slow start. cwnd is now {}", self.token.as_usize(), self.congestion_window);
        } else {
            // RFC 5681: This provides an acceptable approximation to the underlying principle of increasing cwnd by 1 full-sized segment per RTT.
            let mss = self.mss as u32;
            self.congestion_window += mss * mss / self.congestion_window;
        }

    }

    pub fn increment_sequence_number(&mut self, length: u32) {
        self.sequence_number += length;
        debug!("UPDATE_SEQUENCE_NUMBER {}: Incrementing SEQ by {} to {}", self.token.as_usize(), length, self.sequence_number);
    }

    pub fn retransmit_last_packet<H: Handler<Message=TraxiMessage, Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) {
        if let Some(segment) = self.retransmission_queue.get(0) {
            let data = segment.data.clone();
            let sequence_number = segment.sequence_number;

            debug!("RETRANSMIT_LAST_PACKET {}| RETRANSMITTING SEGMENT {}",
                   self.token.as_usize(), sequence_number);

            let packet = PacketType::TCP(TCP::Data(data, sequence_number));
            let message = TraxiMessage::QueuePacket(packet, self.token);
            let sender = event_loop.channel();
            sender.send(message).unwrap();

        }   else {
            debug!("RETRANSMIT_LAST_PACKET {}| RETRANSMIT CALLED BUT NO PACKET AVAILABLE!!",
                   self.token.as_usize());
        }
    }


    /// A valid segment should be RCV.NXT == SEG.SEQ.
    pub fn is_valid_segment(&self, packet_sequence_number: u32) -> bool {
        self.acknowledgement_number == packet_sequence_number
    }

    // TODO: Handle HUP?
    pub fn reregister<H: Handler<Message = TraxiMessage>>(&mut self, mut event_loop: &mut EventLoop<H>) -> Result<()> {
        // Only register for new reads if the read queue isn't excessively large.
        if self.read_queue.len() < 10 {
            debug!("REREGISTER {}| Registering for reads again.", self.token.as_usize());
            self.interest.insert(EventSet::readable());
        } else {
            debug!("REREGISTER {}| READ QUEUE FULL. NOT REGISTERING FOR READS.", self.token.as_usize());
            self.interest.remove(EventSet::readable());
        }

        if let Some(ref socket) = self.socket {
            event_loop.reregister(socket, self.token, self.interest, PollOpt::edge() | PollOpt::oneshot())
        }   else {
            Ok(())
        }
    }

    // Private Functions

    /// [RFC 5681 3.2](https://www.rfc-editor.org/rfc/pdfrfc/rfc5681.txt.pdf)
	/// 3 duplicate ACKs (as defined in section 2, without any intervening ACKs which move SND.UNA) as an indication that a segment has been lost.
    pub fn should_enter_fast_retransmit(&self) -> bool {
        let should_enter_fast_retransmit = self.duplicate_ack_count == 3;
        if should_enter_fast_retransmit {
            error!("SESSION {}| TRANSMISSION LOSS DETECTED! ENTERING FAST RETRANSMIT: UNA: {} RECOVER: {}", self.token.as_usize(), self.unacknowledged, self.sequence_number);
        }

        should_enter_fast_retransmit
    }

    fn send_data_segment<H: Handler<Message=TraxiMessage, Timeout=TraxiMessage>>(&mut self, data: Vec<u8>, event_loop: &mut EventLoop<H>) {
        // Build segment
        let sequence_number = self.sequence_number;
        let segment = TCPSegment::new(data.clone(), sequence_number);
        let segment_length = segment.len() as u32;

        // Add segment to retransmission queue.
        self.retransmission_queue.push_back(segment);

        let sender = event_loop.channel();
        let packet = PacketType::TCP(TCP::Data(data, sequence_number));
        let message = TraxiMessage::QueuePacket(packet, self.token);

        debug!("SEND_DATA {}: Sending segment {} to queue", self.token.as_usize(), sequence_number);

        // Send packet to event loop.
        sender.send(message).unwrap();

        // Increment sequence number.
        self.increment_sequence_number(segment_length);

        // Start the retransmission timer.
        self.retransmission_timer.start_timer(event_loop, self.token);
    }

    /// The slow start algorithm is used when cwnd < ssthresh, while the congestion avoidance algorithm is used when cwnd > ssthresh.  When
    /// cwnd and ssthresh are equal, the sender may use either slow start or congestion avoidance.
    fn should_use_slow_start(&self) -> bool {
        self.congestion_window <= self.slow_start_threshold
    }

    /// [RFC5681 2](https://tools.ietf.org/html/rfc5681#section-2)
    /// The amount of data that has been sent but not yet cumulatively acknowledged.
    fn flight_size(&self) -> u32 {
        self.retransmission_queue.iter()
            .fold(0, |acc, ref segment| acc + segment.data.len() as u32)
    }

    fn enter_fast_retransmit(&mut self) {
        // RFC6582 3.2 Step 2: recover is incremented to the value of the highest sequence number
        // transmitted by the TCP so far.
        let recover = self.sequence_number;
        self.entered_fast_retransmit = Some(recover);

        let flight_size = self.flight_size();

        // RFC5681 3.1 Step 2: When the third duplicate ACK is received, a TCP MUST set ssthresh
        // to no more than the value given in equation [ssthresh = max(FlightSize / 2, 2*SMSS)]
        self.slow_start_threshold = cmp::max((flight_size / 2), self.mss as u32 * 2);

        // RFC5681 3.1 Step 3: cwnd set to ssthresh plus 3*SMSS
        self.congestion_window = self.slow_start_threshold + (3 * self.mss as u32);

        debug!("ENTER_FAST_RETRANSMIT {}| recover: {} - cwnd: {} - ssthresh {} - FlightSize - {}",
               self.token.as_usize(), recover, self.congestion_window, self.slow_start_threshold, flight_size);
    }

    fn enter_fast_recovery(&mut self, acknowledgement_number: u32) {
        debug!("ENTER_FAST_RECOVERY {}| Exiting Fast Retransmit: UNA: {} - ACK: {} - cwnd: {} - ssthresh: {}",
               self.token.as_usize(), self.unacknowledged, acknowledgement_number, self.congestion_window, self.slow_start_threshold);

        // RFC5681 Section 3.1 Step 6: When the next ACK arrives that acknowledges previously unacknowledged
        // data, a TCP MUST set cwnd to ssthresh.
        self.congestion_window = self.slow_start_threshold;

        debug!("ENTER_FAST_RETRANSMIT {}| Entered Fast Recovery: cwnd: {} - ssthresh: {}",
               self.token.as_usize(), self.congestion_window, self.slow_start_threshold);
    }
}

// Functions.

fn create_socket<T: Environment>(socket_addr: &SocketAddr, environment: &T) -> TraxiTunnelResult<TcpStream> {
    let socket = match TcpBuilder::new_v4() {
        Ok(socket)  => socket,
        Err(e) => {
            debug!("Encountered an error creating the socket: {:?}", e);
            // Some sort of error creating the socket. In the wild, we've only seen this caused by
            // the process running out of file descriptors, but we (un)wisely squelch all errors
            // here.
            return Err(TraxiError::from(e));
        },
    };

    let stream = match socket.to_tcp_stream() {
        Ok(stream)  => stream,
        Err(e)      => {
            debug!("Encountered an error converting {:?} to stream: {:?}; dropping SYN packet", socket, e);
            return Err(TraxiError::from(e));
        }
    };

    let protected = environment.protect(stream.as_raw_fd());
    if ! protected {
        // FIXME - The following line causes test_cant_protect_socket to fail, because when it
        // tries to print something inside socket, it .unwrap()s a None value.
        // debug!("Could not protect the socket {:?}; dropping SYN packet", socket);
        debug!("Could not protect the socket; dropping SYN packet");
        return Err(TraxiError::TunnelError("Unable to protect a socket".to_string()));
    }

    match TcpStream::connect_stream(stream, socket_addr) {
        Ok(s)  => Ok(s),
        Err(e) => Err(TraxiError::from(e)),
    }
}

pub fn get_socket_uid(source_ip: Ipv4Addr, source_port: u16) -> Option<usize> {
    // Convert the IP address into a Vec of 0 padded, 2 character wide hex strings.
    let mut source_ip = source_ip.octets().into_iter().map(|x| format!("{:02X}", x)).collect::<Vec<String>>();

    // The kernel stores IP addresses in network format (right to left), so reverse the vec.
    source_ip.reverse();

    // Join them together in one big string.
    let source_ip = source_ip.join("");

    // The port needs to be a 0 padded 4 character wide hex string.
    let connection_string = format!("{}:{:04X}", source_ip, source_port);

    debug!("Searching for connection string: {}", connection_string);

    let (file1, file2) = get_proc_files();
    find_connection_string_in_file(file1, &connection_string)
        .or_else(|| find_connection_string_in_file(file2, &connection_string))
}

/// [RFC 793 3.3](https://tools.ietf.org/html/rfc793#section-3.3)
/// A segment on the retransmission queue is fully acknowledged if the sum of its sequence number and length is less
/// or equal than the acknowledgment value in the incoming segment.
fn is_fully_acknowledged(packet_acknowledgement: u32, sequence_number: u32, packet_length: usize) -> bool {
    let sum = sequence_number + packet_length as u32;
    sum <= packet_acknowledgement
}

fn find_connection_string_in_file(file: Result<File>, connection_string: &str) -> Option<usize> {
    if let Err(e) = file {
        error!("GET_SOCKET_UID| Unable to open proc file: {:?}", e);
        return None;
    }

    let mut file = match file {
        Ok(e)  => e,
        Err(_) => { return None; }
    };
    let mut proc_file = String::new();

    if let Err(e) = file.read_to_string(&mut proc_file) {
        error!("GET_SOCKET_UID| Error reading proc file: {:?}", e);
        return None;
    }

    for line in proc_file.lines() {
        if line.contains(&connection_string) {
            let mut split = line.split_whitespace();
            let uid = split.nth(7).and_then(|x| usize::from_str(x).ok());
            return uid;
        }
    }

    None
}

fn get_window_scaling_factor(tcp_header: &TcpPacket) -> Option<u16> {
    tcp_header.get_options_iter()
        .find(|option| option.get_number() == TcpOptionNumbers::WSCALE)
        .and_then(|mss_field| {
            let mut reader = Cursor::new(mss_field.payload());
            reader.read_u8().ok()
        })
        .map(|n| n as u16)
}

#[cfg(not(target_os="android"))]
fn get_proc_files() -> (Result<File>, Result<File>) {
    (File::open("test_proc"), File::open("test_proc"))
}

#[cfg(target_os="android")]
fn get_proc_files() -> (Result<File>, Result<File>) {
    (File::open("/proc/net/tcp6"), File::open("/proc/net/tcp"))
}
#[cfg(test)]
mod tests {
    extern crate test;
    extern crate log4rs;

    use super::*;
    use tcp::segment::TCPSegment;
    use self::test::Bencher;
    use tunnel::TraxiMessage;
    use std::collections::VecDeque;
    use test_utils::*;

    struct TestHandler;
    impl Handler for TestHandler {
        type Timeout = TraxiMessage;
        type Message = TraxiMessage;

        fn ready(&mut self, _: &mut EventLoop<TestHandler>, _: Token, _: EventSet) { }
    }

    #[test]
    fn test_build_tcp_session() {
        drop(log4rs::init_file("config/test.yaml", Default::default()));
        let test_packet = vec![0x45, 0x00,
            0x00, 0x3c, 0x22, 0x58, 0x40, 0x00, 0x40, 0x06, 0x93, 0xeb, 0xc0, 0xa8, 0x01, 0xb8, 0xc0, 0xa8,
            0x01, 0x70, 0xa1, 0x7f, 0x00, 0x17, 0x33, 0xea, 0x37, 0xf6, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
            0x39, 0x08, 0x84, 0xa7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x0f,
            0x15, 0xae, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x06
        ];

        let expected_destination_ip = Ipv4Addr::new(192,168,1,112);
        let expected_source_ip = Ipv4Addr::new(192,168,1,184);
        let fake_environment = FakeEnvironment;

        let tcp_session = TCPSession::new(&test_packet[..], &fake_environment).unwrap();

        assert_eq!(tcp_session.source_ip, expected_source_ip);
        assert_eq!(tcp_session.destination_ip, expected_destination_ip);
        assert_eq!(tcp_session.state, TCPState::Closed);
        assert_eq!(tcp_session.mss, 1460);
        assert_eq!(tcp_session.receiver_window, 934400);
        assert_eq!(tcp_session.congestion_window, 4380);
        assert_eq!(tcp_session.unacknowledged, tcp_session.sequence_number);
    }

    #[test]
    fn test_get_socket_uid() {
        drop(log4rs::init_file("config/test.yaml", Default::default()));
        let expected_source_ip = Ipv4Addr::new(192,168,1,184);
        let expected_source_port = 0xa17f;

        let uid = get_socket_uid(expected_source_ip, expected_source_port);
        assert_eq!(uid, Some(10230));
    }

    #[test]
    fn test_is_within_congestion_window() {
        drop(log4rs::init_file("config/test.yaml", Default::default()));
        let mut test_session = test_session();
        test_session.receiver_window = 2;

        let test_packet_length = 1;
        assert!(test_session.is_within_congestion_window(test_packet_length));

        let test_packet_length = 3;
        assert!(!test_session.is_within_congestion_window(test_packet_length));

        // RFC5681 says we can only send one new segment of new data during Fast Retransmission.
        // We set the "recover" variable to 2, meaning we can only accept recover + mss of data.
        test_session.entered_fast_retransmit = Some(2);

        // Set mss to 1 to keep things simple
        test_session.mss = 1;

        // 2 + 1 = 3, this should be fine:
        assert!(test_session.is_within_congestion_window(3));
    }

    #[test]
    fn test_update_window_size() {
        drop(log4rs::init_file("config/test.yaml", Default::default()));
        use pnet::packet::tcp::{MutableTcpPacket, TcpOption};
        let mut test_packet = vec![0u8; 32];
        let mut test_session = test_session();
        let test_window_size = 8192;
        let window_scaling_factor = 5;
        let test_options = vec![
            TcpOption::mss(1460),
            TcpOption::wscale(window_scaling_factor),
            TcpOption::nop(),
        ];

        let mut tcp_header = MutableTcpPacket::new(&mut test_packet[..]).unwrap();
        tcp_header.set_window(test_window_size);
        tcp_header.set_data_offset(8);
        tcp_header.set_options(&test_options);

        test_session.update_window_size(&tcp_header.to_immutable());

        let expected_window_size = (test_window_size as u32) << window_scaling_factor;
        assert_eq!(test_session.receiver_window, expected_window_size);

        // Make sure the window scaling factor is preserved, even if the next packet doesn't include
        // options.
        let mut next_packet = vec![0u8; 32];
        let mut tcp_header = MutableTcpPacket::new(&mut next_packet[..]).unwrap();
        tcp_header.set_window(test_window_size);
        test_session.update_window_size(&tcp_header.to_immutable());

        assert_eq!(test_session.receiver_window, expected_window_size);
    }

    #[test]
    fn test_update_unacknowledged() {
        drop(log4rs::init_file("config/test.yaml", Default::default()));
        let mut test_session = test_session();
        let mut test_event_loop: EventLoop<TestHandler> = EventLoop::new().unwrap();

        test_session.unacknowledged = 1;

        // Make sure unacknowledged is updated correctly.
        let higher_acknowledgement = 10;
        test_session.update_unacknowledged(higher_acknowledgement, &mut test_event_loop);
        assert_eq!(test_session.unacknowledged, higher_acknowledgement);

        // Make sure that we don't set the unacknowledged lower.
        let lower_acknowledgement = 5;
        test_session.update_unacknowledged(lower_acknowledgement, &mut test_event_loop);
        assert_eq!(test_session.unacknowledged, higher_acknowledgement);
    }

    #[test]
    fn test_check_duplicate_ack() {
        drop(log4rs::init_file("config/test.yaml", Default::default()));
        let mut test_session = test_session();

        let test_duplicate_ack = 15;

        test_session.check_duplicate_ack(test_duplicate_ack);
        assert_eq!(test_session.duplicate_ack_count, 0);
        assert_eq!(test_session.entered_fast_retransmit, None);

        test_session.check_duplicate_ack(test_duplicate_ack);
        assert_eq!(test_session.duplicate_ack_count, 1);
        assert_eq!(test_session.entered_fast_retransmit, None);

        test_session.check_duplicate_ack(test_duplicate_ack);
        assert_eq!(test_session.duplicate_ack_count, 2);
        assert_eq!(test_session.entered_fast_retransmit, None);

        // After 3 duplicate ACKs, enter Fast Retransmit and record the sequence number as "recover".
        test_session.check_duplicate_ack(test_duplicate_ack);
        assert_eq!(test_session.duplicate_ack_count, 3);
        assert_eq!(test_session.entered_fast_retransmit, Some(test_session.sequence_number));

        // During Fast Transmit, ssthresh should be reduced.
        let expected_ssthresh = (test_session.mss * 2) as u32;
        test_session.unacknowledged = test_duplicate_ack;
        test_session.duplicate_ack_count = 2;
        test_session.check_duplicate_ack(test_duplicate_ack); // Enter Fast Retransmit.
        assert_eq!(test_session.slow_start_threshold, expected_ssthresh);

        // During Fast Transmit, set cwnd to ssthresh plus 3 segments.
        test_session.duplicate_ack_count = 3;
        test_session.expand_congestion_window();
        let expected_congestion_window = test_session.slow_start_threshold + (3 * test_session.mss as u32);
        assert_eq!(test_session.congestion_window, expected_congestion_window); // cwnd == ssthresh + 3 * SMSS

        // When Fast Transmit is finished, deflate cwnd
        test_session.check_duplicate_ack(test_duplicate_ack + 1); // Exit Fast Retransmit.
        assert_eq!(test_session.congestion_window, expected_ssthresh); // Deflate cwnd.
        assert_eq!(test_session.duplicate_ack_count, 0);

        // Check to handle cases where we're receiving redundant duplicate ACKs.
        test_session.sequence_number = test_duplicate_ack;
        test_session.check_duplicate_ack(test_duplicate_ack);
        assert_eq!(test_session.duplicate_ack_count, 0);
    }

    #[test]
    fn test_expand_congestion_window() {
        let mut test_session = test_session();
        test_session.congestion_window = 10;
        test_session.mss = 10;
        test_session.slow_start_threshold = 20;

        // cwnd is smaller than ssthresh, use slow start:
        test_session.expand_congestion_window();
        assert_eq!(test_session.congestion_window, 20); // cwnd + mss

        test_session.congestion_window = 21;

        // cwnd is now greater than ssthresh, use congestion avoidance:
        test_session.expand_congestion_window();
        assert_eq!(test_session.congestion_window, 25); // cwnd += SMSS*SMSS/cwnd

        // Don't expand congestion window when duplicate ACKs detected.
        test_session.duplicate_ack_count = 2;
        test_session.expand_congestion_window();
        assert_eq!(test_session.congestion_window, 25); // Previous cwnd
    }

    #[test]
    fn test_flight_size() {
        let mut test_session = test_session();

        // Build up the retransmission_queue
        test_session.retransmission_queue.push_back(TCPSegment::new(vec![0u8; 10], 1));
        test_session.retransmission_queue.push_back(TCPSegment::new(vec![0u8; 10], 11));
        test_session.retransmission_queue.push_back(TCPSegment::new(vec![0u8; 10], 21));

        let expected_flight_size = 30; // The total amount of bytes in the retransmission_queue.
        assert_eq!(test_session.flight_size(), expected_flight_size);
    }

    #[test]
    fn test_increment_sequence_number() {
        let mut test_session = test_session();
        test_session.sequence_number = 0;

        let test_length = 15;
        test_session.increment_sequence_number(test_length);

        assert_eq!(test_session.sequence_number, test_length);
    }

    #[test]
    fn test_is_valid_segment() {
        let mut test_session = test_session();
        test_session.acknowledgement_number = 10;
        let test_sequence_number = 10;

        // SEG.SEQ == RCV.NXT, so this is a valid segment.
        assert!(test_session.is_valid_segment(test_sequence_number));

        // SEG.SEQ > RCV.NXT, so this is not a valid segment.
        assert!(!test_session.is_valid_segment(9001));
    }

    #[test]
    fn test_update_retransmission_queue() {
        let mut test_session = test_session();
        test_session.unacknowledged = 25;

        for n in 0..50 {
            test_session.retransmission_queue.push_back(TCPSegment::new(vec![n], n as u32));
        }

        test_session.update_retransmission_queue(25);

        assert_eq!(test_session.retransmission_queue.len(), 25);
    }

    #[test]
    fn test_flush_read_queue() {
        let mut test_session = test_session();
        let mut test_event_loop: EventLoop<TestHandler> = EventLoop::new().unwrap();

        // Push 50 1 byte segments onto the queue. Use n as an index to verify the correct items
        // have been removed.
        for n in 0..50 {
            test_session.read_queue.push_back(vec![n]);
        }

        // We want the right edge of the window to be 25, so that 25 of our 50 segments will be
        // removed from the queue.
        test_session.unacknowledged = 25;
        test_session.congestion_window = 0;
        test_session.sequence_number = 0;
        test_session.receiver_window = 50;

        // Flush the queue.
        test_session.flush_read_queue(&mut test_event_loop);

        // We should have removed 25 items.
        assert_eq!(test_session.read_queue.len(), 25);

        let first_item_in_queue = test_session.read_queue.get(0).unwrap();
        assert_eq!(&[25], &first_item_in_queue[..]);
    }

    #[bench]
    fn bench_flush_read_queue(b: &mut Bencher) {
        let mut test_session = test_session();
        test_session.unacknowledged = 25;
        let mut test_event_loop: EventLoop<TestHandler> = EventLoop::new().unwrap();
        let mut test_queue = VecDeque::new();
        for _ in 0..50 {
            test_queue.push_back(vec![0u8]);
        }

        b.iter(|| {
            test_session.read_queue = test_queue.clone();
            test_session.flush_read_queue(&mut test_event_loop);
        });
    }

    #[bench]
    fn bench_update_retransmission_queue(b: &mut Bencher) {
        let mut test_session = test_session();
        test_session.unacknowledged = 25;

        let mut test_queue = VecDeque::new();
        for n in 0..50 {
            test_queue.push_back(TCPSegment::new(vec![0u8], n));
        }

        b.iter(|| {
            test_session.retransmission_queue = test_queue.clone();
            test_session.update_retransmission_queue(24);
        });
    }
}
