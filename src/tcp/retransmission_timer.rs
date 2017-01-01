#![allow(dead_code)]

pub use std::time::Duration;
pub use mio::*;
pub use tunnel::TraxiMessage;

const INITIAL_RTO:u64 = 500; // 0.5 seconds

#[derive(Debug, Clone)]
pub struct RetransmissionTimer {
    rto: Duration,
    pub timeout: Option<Timeout>,

}

impl RetransmissionTimer {
    pub fn new() -> RetransmissionTimer {
        RetransmissionTimer {
            rto: Duration::from_millis(INITIAL_RTO),
            timeout: None,
        }
    }

    pub fn start_timer<H: Handler<Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>, token: Token) {
        if self.timeout.is_none() {
            debug!("SET_TIMEOUT {}| Setting timeout for {} seconds.", token.as_usize(), self.rto.as_secs());

            // Set a new timeout.
            let message = TraxiMessage::RetransmitLastSegment(token);
            self.timeout = event_loop.timeout(message, self.rto).ok();
        }   else {
            debug!("SET_TIMEOUT {}| Timer has already started.", token.as_usize());
        }
    }

    pub fn increment_timer<H: Handler<Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>, token: Token) {
        // Cancel the timeout if it's been set already.
        self.clear_timeout(event_loop);

        // Increase RTO
        self.rto = self.rto * 2;

        debug!("INCREMENT_TIMEOUT {}| Incrementing timeout to {} seconds.", token.as_usize(), self.rto.as_secs());

        // Set a new timeout.
        let message = TraxiMessage::RetransmitLastSegment(token);
        self.timeout = event_loop.timeout(message, self.rto).ok();
    }

    pub fn restart_timer<H: Handler<Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>, token: Token) {
        self.clear_timeout(event_loop);

        self.rto = Duration::from_millis(INITIAL_RTO);
        self.start_timer(event_loop, token);

        debug!("RESET_TIMER {}| Timer has been RESET to {} seconds.",
               token.as_usize(), self.rto.as_secs());
    }

    pub fn stop_timer<H: Handler<Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>, token: Token) {
        self.clear_timeout(event_loop);

        self.rto = Duration::from_millis(INITIAL_RTO);

        debug!("STOP_TIMER {}| RTO is now 500ms, timer has been STOPPED.", token.as_usize());
    }

    fn clear_timeout<H: Handler<Timeout=TraxiMessage>>(&mut self, event_loop: &mut EventLoop<H>) {
        // Cancel the timeout if it's been set already.
        if let Some(ref timeout) = self.timeout {
            event_loop.clear_timeout(timeout);
        }

        self.timeout = None;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct TestHandler; 
    impl Handler for TestHandler {
        type Timeout = TraxiMessage;
        type Message = TraxiMessage;
    }
    
    #[test]
    fn test_initial_rto() {
        let retransmission_timer = RetransmissionTimer::new();
        let initial_rto = Duration::from_millis(500);
        assert_eq!(retransmission_timer.rto, initial_rto);
    }

    #[test]
    fn test_start_timer() {
        let mut test_event_loop: EventLoop<TestHandler> = EventLoop::new().unwrap();

        let mut retransmission_timer = RetransmissionTimer::new();
        assert!(retransmission_timer.timeout.is_none());

        retransmission_timer.start_timer(&mut test_event_loop, Token(1));
        assert!(retransmission_timer.timeout.is_some());

        let initial_rto = Duration::from_millis(500);
        assert_eq!(retransmission_timer.rto, initial_rto);
    }

    #[test]
    fn test_stop_timer() {
        let mut test_event_loop: EventLoop<TestHandler> = EventLoop::new().unwrap();

        let mut retransmission_timer = RetransmissionTimer::new();
        assert!(retransmission_timer.timeout.is_none());

        retransmission_timer.start_timer(&mut test_event_loop, Token(1));
        assert!(retransmission_timer.timeout.is_some());

        retransmission_timer.stop_timer(&mut test_event_loop, Token(1));
        assert!(retransmission_timer.timeout.is_none());

        let initial_rto = Duration::from_millis(500);
        assert_eq!(retransmission_timer.rto, initial_rto);
    }

    #[test]
    fn test_increment_timer() {
        let mut test_event_loop: EventLoop<TestHandler> = EventLoop::new().unwrap();
        let initial_rto = Duration::from_millis(500);

        let mut retransmission_timer = RetransmissionTimer::new();
        assert!(retransmission_timer.timeout.is_none());
        assert_eq!(retransmission_timer.rto, initial_rto);

        retransmission_timer.increment_timer(&mut test_event_loop, Token(1));
        assert!(retransmission_timer.timeout.is_some());

        let next_rto = Duration::from_millis(1000);
        assert_eq!(retransmission_timer.rto, next_rto);

    }

    #[test]
    fn test_restart_timer() {
        let mut test_event_loop: EventLoop<TestHandler> = EventLoop::new().unwrap();

        let mut retransmission_timer = RetransmissionTimer::new();
        assert!(retransmission_timer.timeout.is_none());

        retransmission_timer.start_timer(&mut test_event_loop, Token(1));

        let new_rto = Duration::from_millis(9001);
        retransmission_timer.rto = new_rto;

        retransmission_timer.restart_timer(&mut test_event_loop, Token(1));

        // Reset to initial RTO.
        let initial_rto = Duration::from_millis(500);
        assert_eq!(retransmission_timer.rto, initial_rto);
    }
}
