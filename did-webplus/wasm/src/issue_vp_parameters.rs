use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct IssueVPParameters {
    challenge_o: Option<String>,
    domains_vo: Option<Vec<String>>,
    nonce_o: Option<String>,
}

#[wasm_bindgen]
impl IssueVPParameters {
    #[wasm_bindgen]
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
