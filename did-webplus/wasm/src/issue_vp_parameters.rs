use wasm_bindgen::prelude::wasm_bindgen;

/// Parameters for issuing a VP.
#[wasm_bindgen]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueVPParameters {
    #[serde(rename = "challenge")]
    challenge_o: Option<String>,
    #[serde(rename = "domains")]
    domains_vo: Option<Vec<String>>,
    #[serde(rename = "nonce")]
    nonce_o: Option<String>,
}

#[wasm_bindgen]
impl IssueVPParameters {
    /// Creates a new IssueVPParameters with the given challenge, domains, and nonce.
    pub fn new(
        challenge_o: Option<String>,
        domains_vo: Option<Vec<String>>,
        nonce_o: Option<String>,
    ) -> Self {
        Self {
            challenge_o,
            domains_vo,
            nonce_o,
        }
    }
}

impl Into<did_webplus_ssi::IssueVPParameters> for IssueVPParameters {
    fn into(self) -> did_webplus_ssi::IssueVPParameters {
        did_webplus_ssi::IssueVPParameters {
            challenge_o: self.challenge_o,
            domains_vo: self.domains_vo,
            nonce_o: self.nonce_o,
        }
    }
}
