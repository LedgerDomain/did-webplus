use crate::PrivKeyUsage;
use did_webplus_core::{DIDKeyResourceFullyQualified, KeyPurpose};

/// Records the usage of a private key in a cryptographic operation, including several details of what it was used for.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PrivKeyUsageRecord {
    // TODO: rowid (this might need to be optional to account for insertions)
    /// The pub key corresponding to this priv key.
    pub pub_key: mbx::MBPubKey,
    /// The hash of the pub key, used in pre-rotation schemes.
    pub hashed_pub_key: String,
    /// The time at which this priv key was used in a cryptographic operation.
    pub used_at: time::OffsetDateTime,
    /// Details on the usage.  The details can be omitted, but the type of usage is recorded.
    pub usage: PrivKeyUsage,
    /// Specifies the verification method that was used for the usage, if there was one.
    pub verification_method_o: Option<DIDKeyResourceFullyQualified>,
    /// Specifies the KeyPurpose for the usage, if there was one.
    pub key_purpose_o: Option<KeyPurpose>,
}
