use crate::{DIDWebplusWithFragment, PublicKeyParams};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PublicKeyJWK {
    // TODO: kid field is optional; consider taking this out to simplify things.
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid_o: Option<DIDWebplusWithFragment>,
    // Note that this will use the "kty" field in serde to determine the variant of the enum.
    #[serde(flatten)]
    pub public_key_params: PublicKeyParams,
}

impl PublicKeyJWK {
    pub fn said_derivation_value(
        &self,
        hash_function_code: &said::derivation::HashFunctionCode,
        said_o: Option<&str>,
    ) -> Self {
        let mut c = self.clone();
        c.kid_o = c
            .kid_o
            .map(|kid| kid.said_derivation_value(hash_function_code, said_o));
        c
    }
}
