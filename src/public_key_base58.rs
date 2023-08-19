#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PublicKeyBase58(String);

impl TryFrom<String> for PublicKeyBase58 {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // TODO: Validation
        Ok(Self(value))
    }
}
