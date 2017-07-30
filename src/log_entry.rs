use std::ops::Add;
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub uuid: String,
    pub app_id: String,
    pub destination: String,
    pub bytes: usize,
    pub timestamp: String,
}

impl LogEntry {
    pub fn into_kinesis(&self) -> Vec<u8> {
        // Convert the `LogEntry` into a tab separated string that can be parsed by
        // traxi-streaming-data-processor.
        let string = format!("{}\t{}\t{}\t{}\n",
            self.timestamp,
            self.destination,
            self.bytes,
            self.app_id);

        string.into_bytes()
    }

    pub fn hash(&self) -> String {
        format!("{}{}", self.uuid, self.app_id)
    }
}

impl Add for LogEntry {
    type Output = LogEntry;

    fn add(self, other: LogEntry) -> LogEntry {
        LogEntry {
            uuid: self.uuid,
            app_id: self.app_id,
            destination: self.destination,
            bytes: self.bytes + other.bytes,
            timestamp: self.timestamp,
        }
    }
}

impl Ord for LogEntry {
    fn cmp(&self, other: &LogEntry) -> Ordering {
        self.hash().cmp(&other.hash())
    }
}

impl PartialOrd for LogEntry {
    fn partial_cmp(&self, other: &LogEntry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for LogEntry {
    fn eq(&self, other: &LogEntry) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for LogEntry {}
