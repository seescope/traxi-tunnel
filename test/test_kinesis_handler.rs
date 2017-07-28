use rusoto_core::request::{DispatchSignedRequest, HttpResponse, HttpDispatchError};
use rusoto_core::signature::SignedRequest;

use traxi::kinesis_handler::KinesisHandler;
use traxi::test_utils::init_logging;
use traxi::log_entry::LogEntry;

use std::sync::{Mutex};
use std::{thread, time, io};

// Evil, murderous laughter.
lazy_static! {
    static ref REQUESTS: Mutex<u32> = Mutex::new(0);
}


/// This is quite a doozy since KinesisHandler does the actual work we care about in another thread.
/// To get around this limitation, we create a KinesisHandler with a "dummmy" inner client that simply
/// increments a (insert horror music) SHARED MUTEX. We then sleep for a moment for our dark work
/// to complete and then verify that the Universe hasn't imploded.
#[test]
fn test_kinesis_handler() {
    init_logging();

    let mut events = Vec::new();

    // Kinesis has a hard limit of 500 records per request, so we want to make sure that we make
    // two separate calls.
    for i in 0..500 {
        events.push({
            LogEntry {
                uuid: "abc-123".to_string(),
                destination: "somewhere".to_string(),
                app_id: format!("{}", i),
                bytes: 0,
                timestamp: "something".to_string(),
            }
        });
    }

    for i in 0..500 {
        events.push({
            LogEntry {
                uuid: "abc-456".to_string(),
                destination: "somewhere".to_string(),
                app_id: format!("{}", i),
                bytes: 0,
                timestamp: "something".to_string(),
            }
        });
    }


    let kinesis_handler = KinesisHandler::new_with_tls_client(MockDispatcher);

    kinesis_handler.send_events(events);

    thread::sleep(time::Duration::from_millis(1000));


    assert_eq!(*REQUESTS.lock().unwrap(), 2);

}

struct MockDispatcher;

impl DispatchSignedRequest for MockDispatcher  {
    fn dispatch(&self, _: &SignedRequest) -> Result<HttpResponse, HttpDispatchError> {

        // Sounds of children screaming
        let mut r = REQUESTS.lock().unwrap();
        *r += 1;

        // Look the other way.
        Err(HttpDispatchError::from(io::Error::new(
            io::ErrorKind::Other,
            "Nonsense Error"
        )))
    }
}
