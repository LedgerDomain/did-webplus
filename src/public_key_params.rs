use crate::{Error, PublicKeyParamsEC, PublicKeyParamsOKP};

// Note that this will use the "kty" field in serde to determine the variant of the enum.
#[derive(Clone, Debug, serde::Deserialize, Eq, derive_more::From, PartialEq, serde::Serialize)]
#[serde(tag = "kty")]
pub enum PublicKeyParams {
    EC(PublicKeyParamsEC),
    OKP(PublicKeyParamsOKP),
}

impl From<&dyn selfsign::Verifier> for PublicKeyParams {
    fn from(verifier: &dyn selfsign::Verifier) -> Self {
        match verifier.key_type() {
            selfsign::KeyType::Ed25519 => PublicKeyParamsOKP::try_from(verifier)
                .expect("programmer error")
                .into(),
        }
    }
}

impl TryFrom<&PublicKeyParams> for selfsign::KERIVerifier<'_> {
    type Error = Error;
    fn try_from(public_key_params: &PublicKeyParams) -> Result<Self, Self::Error> {
        match public_key_params {
            PublicKeyParams::EC(public_key_params_ec) => public_key_params_ec.try_into(),
            PublicKeyParams::OKP(public_key_params_okp) => public_key_params_okp.try_into(),
        }
    }
}
