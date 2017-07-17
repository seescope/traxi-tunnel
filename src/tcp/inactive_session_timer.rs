use std::time::Duration;
use mio::{Token, EventLoop, Handler, Timeout};
use tunnel::TraxiMessage;

const SESSION_TIMEOUT_LENGTH:u64 = 3600; // 1 Hour

#[derive(Debug, Clone)]
pub struct InactiveSessionTimer {
    message: TraxiMessage,
    pub timeout: Option<Timeout>,
}


/// Wrapper around a Timeout that will close the session after a predetermined (default 60 min)
/// period of inactivity. This is standard behaviour on most firewalls, as it prevents stale
/// sessions lingering around consuming resources.
/// This is particularly important on Android as a failure to do so will result in a complete
/// deadlock of the system, as new sockets cannot be opened because all the avaialble `fd`s have
/// been consumed.
impl InactiveSessionTimer {
    pub fn new (token: Token) -> InactiveSessionTimer {
        let message = TraxiMessage::CloseTCPSession(token);
        debug!("NEW_TIMER {:?}| TIMER STARTED. SESSION WILL CLOSE IN 60 MINUTES", token);

        InactiveSessionTimer {
            timeout: None,
            message: message,
        }
    }

    /// Used to indicate that the session is active again. Cancels the existing timeout and starts
    /// it up again. Similar to a [Dead man's switch](https://en.wikipedia.org/wiki/Dead_man%27s_switch)
    pub fn restart_timer<H: Handler<Timeout=TraxiMessage>> (&mut self, event_loop: &mut EventLoop<H>)-> () {
        if let Some(ref timeout) = self.timeout {
            match self.message {
                TraxiMessage::CloseTCPSession(token) => {
                    debug!("NEW_TIMER {:?}| TIMER STARTED. SESSION WILL CLOSE IN 60 MINUTES", token);
                    event_loop.clear_timeout(timeout);
                }
                _ => {}
            }
        }

        self.timeout = event_loop.timeout(self.message.clone(), Duration::from_secs(SESSION_TIMEOUT_LENGTH)).ok();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mio::Token;

    #[test]
    fn test_new() {
        let token = Token(1);
        let inactive_session_timer = InactiveSessionTimer::new(token);

        assert!(inactive_session_timer.timeout.is_none());

        match inactive_session_timer.message {
            TraxiMessage::CloseTCPSession(token) => {
                assert_eq!(token, Token(1));
            }
            _ => panic!("self.message is not a CloseTCPSession")
        }
    }
}
