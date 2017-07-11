use std::result;
use std::sync::mpsc::{Sender, channel};
use std::{thread, time};

use rusoto_credential::{ProvideAwsCredentials, AwsCredentials, CredentialsError};
use rusoto_kinesis::{KinesisClient, PutRecordsInput, PutRecordsRequestEntry, Kinesis};
use rusoto_core::{default_tls_client, Region};
use rusoto_core::request::DispatchSignedRequest;

use chrono::{Duration, UTC};

type LogQueue = Vec<(String, Vec<u8>)>;

// Take a batch of `Log`s from `AppLogger` and put the records on our Kinesis stream to be processed.
fn send_events<D: DispatchSignedRequest>(client: &KinesisClient<KinesisCredentials, D>, log_queue: LogQueue) -> () {
    let stream_name = stream_name();

    debug!("SEND_EVENTS| Sending {} events to Kinesis stream {}", log_queue.len(), stream_name);

    // AWS will *SILENTLY_DROP* records after 500. Send in chunks of 500 to get around this.
    for chunk in log_queue.clone().chunks(500) {
        let records: Vec<PutRecordsRequestEntry> = chunk.to_vec().into_iter().map(|(UUID, data)| {
            PutRecordsRequestEntry {
                data: data,
                explicit_hash_key: None,
                partition_key: UUID,
            }
        }).collect();

        let put_records_input = PutRecordsInput {
            records: records,
            stream_name: stream_name.clone(),
        };

        // This has not been known to fail ever in production, so no real error recovery is in
        // place here. However, logs are printed for posterity.
        match client.put_records(&put_records_input) {
            Ok(ref records_output) => {
                match records_output.failed_record_count {
                    Some(0) | None => {
                        debug!("SEND_EVENTS| Successfully sent {} events to Kinesis.", records_output.records.len());
                    }
                    Some(failed_record_count) => {
                        error!("SEND_EVENTS| {} events failed to be sent to Kinesis. Printing errors:", failed_record_count);

                        // Some events may have failed. Print error message.
                        for record in &records_output.records {
                            if let Some(ref error_message) = record.error_message {
                                error!("SEND_EVENTS| Error sending: {}", error_message);
                            }
                        }
                    }
                }
            }
            Err(ref error) => {
                error!("SEND_EVENTS| Unable to send events to Kinesis: {:?}", error);
            }
        }
    }
}

pub struct KinesisHandler {
    tx: Sender<LogQueue>
}

/// Wrapper around a channel to a worker thread that does the actual work of communicating
/// with Kinesis.
impl KinesisHandler {
    /// Create a new KinesisHandler using the default TLS client provided by Rusoto.
    pub fn new() -> KinesisHandler {
        let tls_client = default_tls_client().unwrap();
        KinesisHandler::new_with_tls_client(tls_client)
    }

    // Handy test function.
    pub fn new_with_tls_client<D: 'static + DispatchSignedRequest + Send>(client: D) -> KinesisHandler {
        let (tx, rx) = channel();

        // Create a worker thread that takes ownership of the `Receiver` and `client`.
        thread::spawn(move || {
            let client = KinesisClient::new(client, KinesisCredentials{}, Region::ApSoutheast2);

            // Receive messages from the main thread, sleeping for a second between cycles.
            loop {
                let log_queue = rx.recv().unwrap();
                send_events(&client, log_queue);
                thread::sleep(time::Duration::from_millis(1000));
            }
        });

        KinesisHandler {
            tx: tx
        }
    }

    /// Takes the event and sends it to the worker thread for processing.
    pub fn send_events(&self, log_queue: LogQueue) -> () {
        match self.tx.send(log_queue) {
            Err(e) => error!("Unable to send log_queue: {:?}", e),
            _ => (),
        }
    }
}

#[cfg(test)]
fn stream_name() -> String { "traxi-test".to_string() }

#[cfg(not(test))]
fn stream_name() -> String { "traxi-logs".to_string() }


struct KinesisCredentials;

impl ProvideAwsCredentials for KinesisCredentials {
    fn credentials(&self) -> result::Result<AwsCredentials, CredentialsError> {
        let access_key_id = "AKIAIG3LQD7SGZSJ75WQ";
        let secret_access_key = "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";
        let expiry_time = UTC::now() + Duration::seconds(600);
        Ok(AwsCredentials::new(access_key_id, secret_access_key, None, expiry_time))
    }
}
