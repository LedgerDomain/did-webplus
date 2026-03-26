use wasm_bindgen::prelude::wasm_bindgen;

use crate::{DID, KeyPurpose};

#[wasm_bindgen]
pub struct VerificationMethodRecord(did_webplus_wallet_store::VerificationMethodRecord);

#[wasm_bindgen]
impl VerificationMethodRecord {
    /// Returns the DID of this verification method.
    pub fn did(&self) -> DID {
        self.0
            .did_key_resource_fully_qualified
            .did()
            .to_owned()
            .into()
    }
    /// Returns the "selfHash" field of the version of the DID for this verification method.
    pub fn query_self_hash(&self) -> String {
        self.0
            .did_key_resource_fully_qualified
            .query_self_hash()
            .to_string()
    }
    /// Returns the "versionId" field of the version of the DID for this verification method.
    pub fn query_version_id(&self) -> u32 {
        self.0.did_key_resource_fully_qualified.query_version_id()
    }
    /// Returns true iff the given key purpose is present in this verification method.
    pub fn has_key_purpose(&self, key_purpose: KeyPurpose) -> bool {
        let key_purpose: did_webplus_core::KeyPurpose = key_purpose.into();
        self.0.key_purpose_flags.contains(key_purpose)
    }
    /// Returns the list of key purposes for this verification method.
    pub fn key_purposes(&self) -> Vec<KeyPurpose> {
        let mut key_purpose_v = Vec::new();
        for key_purpose in did_webplus_core::KeyPurpose::VERIFICATION_METHOD_VARIANTS {
            if self.0.key_purpose_flags.contains(key_purpose) {
                key_purpose_v.push(KeyPurpose::from(key_purpose));
            }
        }
        key_purpose_v
    }
    /// Returns the public key (in multihash format) for this verification method.
    pub fn pub_key(&self) -> String {
        self.0.pub_key.to_string()
    }
}

impl From<VerificationMethodRecord> for did_webplus_wallet_store::VerificationMethodRecord {
    fn from(verification_method_record: VerificationMethodRecord) -> Self {
        verification_method_record.0
    }
}

impl From<did_webplus_wallet_store::VerificationMethodRecord> for VerificationMethodRecord {
    fn from(
        verification_method_record: did_webplus_wallet_store::VerificationMethodRecord,
    ) -> Self {
        Self(verification_method_record)
    }
}
