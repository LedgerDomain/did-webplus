use did_webplus::{KeyPurpose, DID};

#[derive(Default)]
pub struct LocallyControlledVerificationMethodFilter {
    pub did_o: Option<DID>,
    pub version_id_o: Option<u32>,
    pub key_purpose_o: Option<KeyPurpose>,
}
