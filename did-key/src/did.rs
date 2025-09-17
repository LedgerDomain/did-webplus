use crate::{DIDStr, Error};

#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_did_key_str", borrow = "DIDStr")]
#[cfg_attr(feature = "serde", pneu_string(deserialize, serialize))]
pub struct DID(String);

impl TryFrom<&selfsign::VerifierBytes<'_>> for DID {
    type Error = Error;
    fn try_from(verifier_bytes: &selfsign::VerifierBytes<'_>) -> Result<Self, Self::Error> {
        let multibase_string = match verifier_bytes.key_type {
            selfsign::KeyType::Ed25519 => {
                let verifier_encoded = ssi_multicodec::MultiEncodedBuf::encode_bytes(
                    ssi_multicodec::ED25519_PUB,
                    verifier_bytes.verifying_key_byte_v.as_ref(),
                );
                multibase::encode(multibase::Base::Base58Btc, &verifier_encoded)
            }
            selfsign::KeyType::Secp256k1 => {
                let verifier_encoded = ssi_multicodec::MultiEncodedBuf::encode_bytes(
                    ssi_multicodec::SECP256K1_PUB,
                    verifier_bytes.verifying_key_byte_v.as_ref(),
                );
                multibase::encode(multibase::Base::Base58Btc, &verifier_encoded)
            }
        };
        Ok(Self(format!("did:key:{}", multibase_string)))
    }
}
