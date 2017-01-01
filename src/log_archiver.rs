use super::Result;
use std::result;
use std::io::prelude::*;
use std::io::{Cursor, BufReader};
use std::fs::File;

use zip::{ZipWriter, CompressionMethod};

use rusoto::{ProvideAwsCredentials, AwsCredentials, Region, AwsError};
use rusoto::s3::S3Helper;

use chrono::{Duration, UTC, Local};

pub struct Archiver {
    log_file_path: String,
    user_id: String
}

impl Archiver {
    pub fn new(log_file_path: String, user_id: String) -> Archiver {
        Archiver { 
            log_file_path: log_file_path,
            user_id: user_id
        }
    }

    pub fn upload(&self) -> Result<()> {
        let zip_file = try!(self.write_zip_file());
        self.upload_archive(&zip_file)
    }

    fn write_zip_file(&self) -> Result<Vec<u8>> {
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let mut buffer = [0u8; 4096];
        let file = try!(File::open(&self.log_file_path));
        let mut file_buffer = BufReader::new(file);
        let file_name = self.log_file_name("log");

        try!(zip.start_file(file_name, CompressionMethod::Deflated));

        while let Ok(bytes_read) = file_buffer.read(&mut buffer) {
            if bytes_read == 0 { break };
            try!(zip.write(&buffer));
        }

        Ok(try!(zip.finish()).into_inner())
    }

    fn upload_archive(&self, archive: &[u8]) -> Result<()> {
        let helper = S3Helper::new(ArchiverCredentials{}, Region::ApSoutheast2);
        let file_name = self.log_file_name("zip");
        try!(helper.put_object("traxi-logs", &file_name, archive));

        Ok(())
    }

    fn log_file_name(&self, extension: &str) -> String {
        let yesterday = Local::now() - Duration::hours(24);
        format!("{}-{}.{}", yesterday.format("%Y-%m-%d"), self.user_id, extension)
    }
}

struct ArchiverCredentials;

impl ProvideAwsCredentials for ArchiverCredentials {
    fn credentials(&self) -> result::Result<AwsCredentials, AwsError> {
        let access_key_id = "AKIAIG3LQD7SGZSJ75WQ";
        let secret_access_key = "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";
        let expiry_time = UTC::now() + Duration::seconds(600);
        Ok(AwsCredentials::new(access_key_id, secret_access_key, None, expiry_time))
    }
}

#[cfg(test)]
mod tests {
    use log_archiver::{Archiver};

    #[test]
    #[ignore]
    fn it_uploads() {
        let archiver = Archiver::new(
            "test/sample-data/test_log_file".to_string(),
            "test_user".to_string()
        );

        assert!(archiver.upload().is_ok());
    }
}
