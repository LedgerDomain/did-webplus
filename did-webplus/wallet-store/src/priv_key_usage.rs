use crate::{PrivKeyUsageType, Result};
use did_webplus_core::{DIDFullyQualified, DIDKeyResourceFullyQualified, DID};

/// Specific usages for a private key, along with type-specific data that does NOT include signature data.
// TODO: Figure out if the other pub key in a key exchange is a risk to store.
#[derive(Clone, Debug)]
pub enum PrivKeyUsage {
    /// Optionally contains the DID that was created.
    DIDCreate { created_did_o: Option<DID> },
    /// Optionally contains the DIDFullyQualified that resulted from the update.
    DIDUpdate {
        updated_did_fully_qualified_o: Option<DIDFullyQualified>,
    },
    /// Optionally contains the signing input for the signing operation.
    Sign { signing_input_o: Option<Vec<u8>> },
    /// Optionally contains the signing input for the JWS that was produced.  Note that this specific format
    /// doesn't support detached, unencoded JWS payloads.
    SignJWS { signing_input_o: Option<String> },
    /// Optionally contains the signing input for the JWT that was produced.
    SignJWT { signing_input_o: Option<String> },
    /// Optionally contains the unsigned VC.
    // TODO: Figure out if this is well-defined for JSON-LD
    SignVC { unsigned_vc_o: Option<String> },
    /// Optionally contains the unsigned VP.
    // TODO: Figure out if this is well-defined for JSON-LD
    SignVP { unsigned_vp_o: Option<String> },
    /// Contains the other pub key that was used in the key exchange.
    // TODO: Is this a risk?  Since the wallet contains this priv key, the shared secret could be derived from this
    // priv key and the other pub key.  Because encrypted communication typically involves generating an ephemeral
    // keypair for the session, and only using the shared secret to encrypt that, this would only be a risk if the
    // comms channel could be monitored (past or future).
    KeyExchange { other_o: Option<mbx::MBPubKey> },
    /// Contains the DID URI for the other pub key that was used in the key exchange.
    // TODO: Is this a risk?  Since the wallet contains this priv key, the shared secret could be derived from this
    // priv key and the other pub key.  Because encrypted communication typically involves generating an ephemeral
    // keypair for the session, and only using the shared secret to encrypt that, this would only be a risk if the
    // comms channel could be monitored (past or future).
    KeyExchangeWithDID {
        other_o: Option<DIDKeyResourceFullyQualified>,
    },
    /// Generic usage data for usage that doesn't fit into the other categories.
    Generic { usage_spec_o: Option<Vec<u8>> },
}

impl PrivKeyUsage {
    pub fn priv_key_usage_type(&self) -> PrivKeyUsageType {
        match self {
            Self::DIDCreate { .. } => PrivKeyUsageType::DIDCreate,
            Self::DIDUpdate { .. } => PrivKeyUsageType::DIDUpdate,
            Self::Sign { .. } => PrivKeyUsageType::Sign,
            Self::SignJWS { .. } => PrivKeyUsageType::SignJWS,
            Self::SignJWT { .. } => PrivKeyUsageType::SignJWT,
            Self::SignVC { .. } => PrivKeyUsageType::SignVC,
            Self::SignVP { .. } => PrivKeyUsageType::SignVP,
            Self::KeyExchange { .. } => PrivKeyUsageType::KeyExchange,
            Self::KeyExchangeWithDID { .. } => PrivKeyUsageType::KeyExchangeWithDID,
            Self::Generic { .. } => PrivKeyUsageType::Generic,
        }
    }
    // TODO: When everything is a proper newtype, then this could return &[u8]
    pub fn priv_key_usage_spec(&self) -> Option<Vec<u8>> {
        match self {
            Self::DIDCreate { created_did_o } => created_did_o
                .as_ref()
                .map(|created_did| created_did.to_string().as_bytes().to_vec()),
            Self::DIDUpdate {
                updated_did_fully_qualified_o: updated_did_with_query_o,
            } => updated_did_with_query_o
                .as_ref()
                .map(|updated_did_with_query| {
                    updated_did_with_query.to_string().as_bytes().to_vec()
                }),
            Self::Sign { signing_input_o } => signing_input_o
                .as_ref()
                .map(|signing_input| signing_input.to_vec()),
            Self::SignJWS { signing_input_o } => signing_input_o
                .as_ref()
                .map(|signing_input| signing_input.as_bytes().to_vec()),
            Self::SignJWT { signing_input_o } => signing_input_o
                .as_ref()
                .map(|signing_input| signing_input.as_bytes().to_vec()),
            Self::SignVC { unsigned_vc_o } => unsigned_vc_o
                .as_ref()
                .map(|unsigned_vc| unsigned_vc.as_bytes().to_vec()),
            Self::SignVP { unsigned_vp_o } => unsigned_vp_o
                .as_ref()
                .map(|unsigned_vp| unsigned_vp.as_bytes().to_vec()),
            Self::KeyExchange { other_o } => {
                other_o.as_ref().map(|other| other.as_bytes().to_vec())
            }
            Self::KeyExchangeWithDID { other_o } => other_o
                .as_ref()
                .map(|other| other.to_string().as_bytes().to_vec()),
            Self::Generic { usage_spec_o } => {
                usage_spec_o.as_ref().map(|usage_spec| usage_spec.to_vec())
            }
        }
    }
    pub fn try_from_priv_key_usage_type_and_spec(
        _priv_key_usage_type: PrivKeyUsageType,
        _priv_key_usage_spec_o: Option<&[u8]>,
    ) -> Result<Self> {
        unimplemented!();
    }
}
