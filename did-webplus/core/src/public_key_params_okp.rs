use std::str::FromStr;

use crate::Error;

// "kty" of "OKP" is used for curves including "Ed25519".
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyParamsOKP {
    pub crv: String,
    pub x: String,
}

impl PublicKeyParamsOKP {
    /// Convenience function for creating the PublicKeyParamsOKP for an Ed25519 key.
    pub fn ed25519(x: String) -> Self {
        Self {
            crv: "Ed25519".into(),
            x,
        }
    }
}

impl TryFrom<&dyn selfsign::Verifier> for PublicKeyParamsOKP {
    type Error = Error;
    fn try_from(verifier: &dyn selfsign::Verifier) -> Result<Self, Self::Error> {
        match verifier.key_type() {
            selfsign::KeyType::Ed25519 => {
                let keri_verifier = verifier.to_keri_verifier();
                let public_key_base64 = keri_verifier
                    .strip_prefix(verifier.key_type().keri_prefix())
                    .unwrap();
                Ok(Self {
                    crv: "Ed25519".into(),
                    x: public_key_base64.to_string(),
                })
            }
            _ => {
                return Err(Error::Unrecognized(
                    "public key type not supported for PublicKeyParamsOKP",
                ))
            }
        }
    }
}

impl TryFrom<&PublicKeyParamsOKP> for selfsign::KERIVerifier {
    type Error = Error;
    fn try_from(public_key_params_okp: &PublicKeyParamsOKP) -> Result<Self, Self::Error> {
        match public_key_params_okp.crv.as_str() {
            "Ed25519" => selfsign::KERIVerifier::from_str(
                format!(
                    "{}{}",
                    selfsign::KeyType::Ed25519.keri_prefix(),
                    public_key_params_okp.x.as_str()
                )
                .as_str(),
            )
            .map_err(|_| Error::Malformed("Invalid Ed25519 public key")),
            _ => Err(Error::Unrecognized("OKP curve")),
        }
    }
}
