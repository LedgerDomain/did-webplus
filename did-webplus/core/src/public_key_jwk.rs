use crate::{DIDKeyResource, Error, PublicKeyParams};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyJWK {
    // TODO: kid field is optional; consider taking this out to simplify things.
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid_o: Option<DIDKeyResource>,
    // Note that this will use the "kty" field in serde to determine the variant of the enum.
    #[serde(flatten)]
    pub public_key_params: PublicKeyParams,
}

impl TryFrom<&PublicKeyJWK> for mbc::MBPubKey {
    type Error = Error;
    fn try_from(public_key_jwk: &PublicKeyJWK) -> Result<Self, Self::Error> {
        Ok(mbc::MBPubKey::try_from(&public_key_jwk.public_key_params)?)
    }
}
