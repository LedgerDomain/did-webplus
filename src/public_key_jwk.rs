use crate::DIDWebplusWithFragment;

// NOTE: This only supports EC keys for now.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PublicKeyJWK {
    // TODO: kid field is optional; consider taking this out to simplify things.
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid_o: Option<DIDWebplusWithFragment>,
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
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
