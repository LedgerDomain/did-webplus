use crate::{PublicKeyBase58, PublicKeyJWK};

#[derive(Clone, Debug, derive_more::From, serde::Deserialize, serde::Serialize)]
pub enum VerificationMethodPublicKey {
    #[serde(rename = "publicKeyBase58")]
    Base58(PublicKeyBase58),
    #[serde(rename = "publicKeyJwk")]
    JWK(PublicKeyJWK),
}

impl VerificationMethodPublicKey {
    pub fn said_derivation_value(
        &self,
        hash_function_code: &said::derivation::HashFunctionCode,
        said_o: Option<&str>,
    ) -> Self {
        match self {
            Self::Base58(public_key_base58) => Self::Base58(public_key_base58.clone()),
            Self::JWK(public_key_jwk) => {
                Self::JWK(public_key_jwk.said_derivation_value(hash_function_code, said_o))
            }
        }
    }
}
