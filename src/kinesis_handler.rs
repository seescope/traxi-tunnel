use std::result;
use std::thread::{spawn, JoinHandle};
use rusoto::{ProvideAwsCredentials, AwsCredentials, Region, AwsError};
use rusoto::kinesis::{KinesisClient, PutRecordsInput, PutRecordsRequestEntry, PutRecordsError, PutRecordsOutput};

type KinesisResult = Result<PutRecordsOutput, PutRecordsError>;
use chrono::{Duration, UTC};

#[cfg(test)]
fn stream_name() -> String { "traxi-test".to_string() }

#[cfg(not(test))]
fn stream_name() -> String { "traxi-logs".to_string() }

pub fn send_events(log_queue: Vec<(String, Vec<u8>)>) -> JoinHandle<Vec<KinesisResult>> {
    let stream_name = stream_name();
    debug!("SEND_EVENTS| Sending {} events to Kinesis stream {}", log_queue.len(), stream_name);

    spawn(move || {
        let client = KinesisClient::new(KinesisCredentials{}, Region::ApSoutheast2);
        log_queue.clone().chunks(500).map(|chunk| {
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

            let result = client.put_records(&put_records_input);
            match result {
                Ok(ref records_output) => {
                    match records_output.failed_record_count {
                        Some(0) | None => {
                            debug!("SEND_EVENTS| Successfully sent {} events to Kinesis.", records_output.records.len());
                        }
                        Some(failed_record_count) => {
                            error!("SEND_EVENTS| {} events failed to be sent to Kinesis. Printing errors:", failed_record_count);

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

            result
        }).collect()
    })
}

struct KinesisCredentials;

impl ProvideAwsCredentials for KinesisCredentials {
    fn credentials(&self) -> result::Result<AwsCredentials, AwsError> {
        let access_key_id = "AKIAIG3LQD7SGZSJ75WQ";
        let secret_access_key = "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";
        let expiry_time = UTC::now() + Duration::seconds(600);
        Ok(AwsCredentials::new(access_key_id, secret_access_key, None, expiry_time))
    }
}
