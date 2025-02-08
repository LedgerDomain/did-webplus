use crate::PrivKeyUsage;
use did_webplus_core::{DIDKeyResourceFullyQualified, KeyPurpose};

/// Records the usage of a private key in a cryptographic operation, including several details of what it was used for.
#[derive(Clone, Debug)]
pub struct PrivKeyUsageRecord {
    /// The pub key corresponding to this priv key.
    pub pub_key: selfsign::KERIVerifier,
    /// The time at which this priv key was used in a cryptographic operation.
    pub used_at: time::OffsetDateTime,
    /// Details on the usage.  The details can be omitted, but the type of usage is recorded.
    pub usage: PrivKeyUsage,
    /// If there was an associated controlled DID, then this is the DID with its key id fragment, and the
    /// KeyPurpose of the usage.
    pub verification_method_and_purpose_o: Option<(DIDKeyResourceFullyQualified, KeyPurpose)>,
}
