use did_webplus_core::{DIDKeyResourceFullyQualified, KeyPurposeFlags};

/// This specifies the membership of a verification method (i.e. pub key) for a specific purpose in a DID doc.
#[derive(Debug)]
pub struct VerificationMethodRecord {
    /// Specifies the DID with its selfHash and versionId query params and key ID fragment.
    pub did_key_resource_fully_qualified: DIDKeyResourceFullyQualified,
    /// Specifies the purposes of this verification method.
    // pub key_purpose_s: HashSet<KeyPurpose>,
    pub key_purpose_flags: KeyPurposeFlags,
    /// Specifies the pub key itself.
    pub pub_key: mbx::MBPubKey,
}
