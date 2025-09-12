use did_webplus_core::{KeyPurpose, DID};

#[derive(Clone, Debug, Default)]
pub struct LocallyControlledVerificationMethodFilter {
    // TODO: Probably need filters for hashed_pub_key, and maybe pub_key.
    pub did_o: Option<DID>,
    pub version_id_o: Option<u32>,
    pub key_purpose_o: Option<KeyPurpose>,
    pub key_id_o: Option<selfsign::KERIVerifier>,
    pub result_limit_o: Option<u32>,
}
