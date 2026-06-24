use did_webplus_core::{DIDKeyResourceFullyQualified, KeyPurposeFlags};

/// This specifies the membership of a verification method (i.e. pub key) for a specific purpose in a DID doc.
#[derive(Debug)]
pub struct VerificationMethodRecord {
    /// Specifies the DID with its selfHash and versionId query params and key ID fragment.
    pub did_key_resource_fully_qualified: DIDKeyResourceFullyQualified,
    /// Specifies the pub key itself.
    pub pub_key: mbx::MBPubKey,
    /// The hash of the pub key, used in pre-rotation schemes.
    // TODO: Make this an appropriate type -- Option<mbx::MBHash> ?  This would have implications
    // in the database schema that would require a migration.
    pub hashed_pub_key: String,
    /// If this is Some(did), then use of this verification method is restricted to the given DID.
    // TODO: Make this an appropriate type.
    pub did_restriction_o: Option<String>,
    /// If this is Some(key_purpose_restriction), then this verification method may only be used for the given purposes.
    /// If None, then there is no restriction.
    pub key_purpose_restriction_o: Option<KeyPurposeFlags>,
    /// The time at which this verification method was created.
    // #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// The time at which this verification method was last used in a cryptographic operation, or None if never used.
    // #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at_o: Option<time::OffsetDateTime>,
    /// If Some(max_usage_count), specifies the maximum number of times this verification method can be used in a cryptographic
    /// before it must be retired.  If None, then there is no restriction.
    pub max_usage_count_o: Option<u32>,
    /// The number of cryptographic operations this verification method has been used for.
    pub usage_count: u32,
    /// If this is Some(time), then this verification method has been deleted at that time.
    // #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at_o: Option<time::OffsetDateTime>,
    /// Optional comment field for this verification method.  Could be used to give a human-readable name, description, or
    /// intented usage for this verification method.
    pub comment_o: Option<String>,
}
