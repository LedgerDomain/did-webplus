use did_webplus_core::KeyPurposeFlags;

// TODO: Consider making a "non-deleted" version of PrivKeyRecord that has those constraints.
#[derive(Debug)]
pub struct PrivKeyRecord {
    /// The pub key corresponding to this priv key.
    pub pub_key: mbc::MBPubKey,
    /// The hash of the pub key, used in pre-rotation schemes.
    // TODO: Make this an appropriate type.
    pub hashed_pub_key: String,
    /// If this is Some(did), then use of this priv key is restricted to the given DID.
    // TODO: Make this an appropriate type.
    pub did_restriction_o: Option<String>,
    /// If this is Some(key_purpose_restriction), then this priv key may only be used for the given purposes.
    /// If None, then there is no restriction.
    pub key_purpose_restriction_o: Option<KeyPurposeFlags>,
    /// The time at which this priv key was created.
    pub created_at: time::OffsetDateTime,
    /// The time at which this priv key was last used in a cryptographic operation, or None if never used.
    pub last_used_at_o: Option<time::OffsetDateTime>,
    /// If Some(max_usage_count), specifies the maximum number of times this key can be used in a cryptographic
    /// before it must be retired.  If None, then there is no restriction.
    pub max_usage_count_o: Option<u32>,
    /// The number of cryptographic operations this priv key has been used for.
    pub usage_count: u32,
    /// If this is Some(time), then this priv key has been deleted at that time.  In this case, the private_key_bytes_o
    /// field will be None.
    pub deleted_at_o: Option<time::OffsetDateTime>,
    /// The priv key, or None if this priv key has been deleted.
    // TODO: REDACT THIS in std::fmt::Debug impl:
    pub private_key_bytes_o: Option<selfsign::PrivateKeyBytes<'static>>,
    /// Optional comment field for this key.  Could be used to give a human-readable name, description, or
    /// intented usage for this key.
    pub comment_o: Option<String>,
}
