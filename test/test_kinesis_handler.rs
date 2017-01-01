use traxi::kinesis_handler::send_events;
use traxi::test_utils::init_logging;

#[test]
#[ignore]
fn test_kinesis_handler() {
    init_logging();

    let mut events = Vec::new();

    for _ in 0..500 {
        events.push(("abc-123".to_string(), vec!(0u8)));
    }

    for _ in 0..500 {
        events.push(("abc-456".to_string(), vec!(0u8)));
    }

    // Make sure that we sent two seperate requests to AWS.
    let results = send_events(events).join().unwrap();
    assert!(results.len() == 2);

    // Assert they were both okay.
    for result in results {
        assert!(result.is_ok());
    }
}
