use super::{Result, TraxiError};
use hyper::client::Client;

pub trait FirebaseConnector {
    fn report_installed(&self) -> Result<()>;
}

#[derive(Debug)]
pub struct Firebase {
    base_url: String
}

impl Firebase {
    pub fn new(base_url: String) -> Firebase {
        Firebase { base_url: base_url }
    }
}

impl FirebaseConnector for Firebase {
    fn report_installed(&self) -> Result<()> {
        let client = Client::new();

        let url = format!("{}.json", self.base_url);
        client.patch(&url)
            .body("{\"status\": \"INSTALLED\"}")
            .send()
            .map(|r| info!("Succesfully reported installed. Response: {:?}", r))
            .map_err(|e| TraxiError::from(e))
    }
}

#[test]
#[ignore]
fn test_report_installed() {
    let firebase_connector = Firebase::new("https://traxitesting.firebaseIO.com/kids/+61401633346".to_string());
    assert!(firebase_connector.report_installed().is_ok());
}
