use crate::{DIDStr, Error, DID_KEY_ED25519_PREFIX, DID_KEY_SECP256K1_PREFIX};
use pneutype::Validate;

#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_did_key_str", borrow = "DIDStr")]
#[cfg_attr(feature = "serde", pneu_string(deserialize, serialize))]
pub struct DID(String);

impl TryFrom<&selfsign::VerifierBytes<'_>> for DID {
    type Error = Error;
    fn try_from(verifier_bytes: &selfsign::VerifierBytes<'_>) -> Result<Self, Self::Error> {
        // Create the byte array that has the two prefix bytes.
        let mut byte_v = Vec::with_capacity(2 + verifier_bytes.verifying_key_byte_v.len());
        match verifier_bytes.key_type {
            selfsign::KeyType::Ed25519 => {
                byte_v.extend_from_slice(&DID_KEY_ED25519_PREFIX);
                byte_v.extend_from_slice(&verifier_bytes.verifying_key_byte_v);
            }
            selfsign::KeyType::Secp256k1 => {
                byte_v.extend_from_slice(&DID_KEY_SECP256K1_PREFIX);
                byte_v.extend_from_slice(&verifier_bytes.verifying_key_byte_v);
            }
        }
        let did_key_string = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, byte_v)
        );
        debug_assert!(
            DIDStr::validate(&did_key_string).is_ok(),
            "programmer error"
        );
        Ok(Self(did_key_string))
    }
}
