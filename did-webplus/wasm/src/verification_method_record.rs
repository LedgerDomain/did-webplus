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
    /// Returns the fully qualified key resource, i.e. the "id" field of the verification method.
    pub fn did_key_resource_fully_qualified(&self) -> String {
        self.0.did_key_resource_fully_qualified.to_string()
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
    /// Returns the public key (in multikey format) for this verification method.
    pub fn pub_key(&self) -> String {
        self.0.pub_key.to_string()
    }
    /// Returns the DID restriction for this verification method.  If None, then there
    /// is no restriction.
    pub fn did_restriction(&self) -> Option<String> {
        self.0.did_restriction_o.clone()
    }
    /// Returns true iff the given key purpose is present in this verification method.
    pub fn has_key_purpose(&self, key_purpose: KeyPurpose) -> bool {
        match self.0.key_purpose_restriction_o {
            Some(key_purpose_restriction) => {
                let key_purpose: did_webplus_core::KeyPurpose = key_purpose.into();
                key_purpose_restriction.contains(key_purpose)
            }
            None => true,
        }
    }
    /// Returns the key purpose restriction for this verification method.  If None, then there
    /// is no restriction.
    pub fn key_purpose_restriction(&self) -> Option<Vec<KeyPurpose>> {
        match self.0.key_purpose_restriction_o {
            Some(key_purpose_restriction) => {
                let mut key_purpose_v = Vec::new();
                for key_purpose in did_webplus_core::KeyPurpose::VERIFICATION_METHOD_VARIANTS {
                    if key_purpose_restriction.contains(key_purpose) {
                        key_purpose_v.push(KeyPurpose::from(key_purpose));
                    }
                }
                Some(key_purpose_v)
            }
            None => None,
        }
    }
    /// Returns the time at which this verification method was created.
    pub fn created_at(&self) -> String {
        self.0.created_at.to_string()
    }
    /// Returns the time at which this verification method was last used in a cryptographic operation.
    pub fn last_used_at(&self) -> Option<String> {
        self.0
            .last_used_at_o
            .map(|last_used_at| last_used_at.to_string())
    }
    /// Returns the maximum number of times this verification method can be used in a cryptographic operation.
    pub fn max_usage_count(&self) -> Option<u32> {
        self.0.max_usage_count_o
    }
    /// Returns the number of times this verification method has been used in a cryptographic operation.
    pub fn usage_count(&self) -> u32 {
        self.0.usage_count
    }
    /// Returns the time at which this verification method has been deleted.
    pub fn deleted_at(&self) -> Option<String> {
        self.0.deleted_at_o.map(|deleted_at| deleted_at.to_string())
    }
    /// Returns the comment for this verification method.  If None, then there is no comment.
    pub fn comment(&self) -> Option<String> {
        self.0.comment_o.clone()
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
