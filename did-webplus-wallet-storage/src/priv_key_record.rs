use did_webplus::KeyPurposeFlags;

// TODO: Consider making a "non-deleted" version of PrivKeyRecord that has those constraints.
#[derive(Debug)]
pub struct PrivKeyRecord {
    /// The pub key corresponding to this priv key.
    pub pub_key: selfsign::KERIVerifier,
    /// If this is Some(key_purpose_restriction), then this priv key may only be used for the given purposes.
    /// If None, then there is no restriction.
    pub key_purpose_restriction_o: Option<KeyPurposeFlags>,
    /// The time at which this priv key was created.
    pub created_at: time::OffsetDateTime,
    /// The time at which this priv key was last used in a cryptographic operation, or None if never used.
    pub last_used_at_o: Option<time::OffsetDateTime>,
    /// The number of cryptographic operations this priv key has been used for.
    pub usage_count: u32,
    /// If this is Some(time), then this priv key has been deleted at that time.  In this case, the priv_jwk_o
    /// field will be None.
    pub deleted_at_o: Option<time::OffsetDateTime>,
    /// The priv key, or None if this priv key has been deleted.
    // TODO: REDACT THIS
    pub private_key_bytes_o: Option<selfsign::PrivateKeyBytes<'static>>,
}
