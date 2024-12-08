use crate::Error;

// "kty" of "EC" is used for curves including "secp256k1", "P-256" (which is sometimes also called "secp256r1"),
// "P-384", and "P-521".
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyParamsEC {
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl PublicKeyParamsEC {
    /// Convenience function for creating the PublicKeyParamsEC for a secp256k1 key.
    pub fn secp256k1(x: String, y: String) -> Self {
        Self {
            crv: "secp256k1".into(),
            x,
            y,
        }
    }
    /// Convenience function for creating the PublicKeyParamsEC for a P-256 key (which is
    /// called secp256r1 in some other contexts).
    pub fn p256(x: String, y: String) -> Self {
        Self {
            crv: "P-256".into(),
            x,
            y,
        }
    }
    /// Convenience function for creating the PublicKeyParamsEC for a P-384 key.
    pub fn p384(x: String, y: String) -> Self {
        Self {
            crv: "P-384".into(),
            x,
            y,
        }
    }
    /// Convenience function for creating the PublicKeyParamsEC for a P-521 key.
    pub fn p521(x: String, y: String) -> Self {
        Self {
            crv: "P-521".into(),
            x,
            y,
        }
    }
}

impl TryFrom<&PublicKeyParamsEC> for selfsign::KERIVerifier {
    type Error = Error;
    fn try_from(public_key_params_ec: &PublicKeyParamsEC) -> Result<Self, Self::Error> {
        match public_key_params_ec.crv.as_str() {
            "secp256k1" => {
                unimplemented!("blah");
            }
            "P-256" => {
                unimplemented!("blah");
            }
            "P-384" => {
                unimplemented!("blah");
            }
            "P-521" => {
                unimplemented!("blah");
            }
            _ => Err(Error::Unrecognized("EC curve")),
        }
    }
}

impl TryFrom<&dyn selfsign::Verifier> for PublicKeyParamsEC {
    type Error = Error;
    fn try_from(verifier: &dyn selfsign::Verifier) -> Result<Self, Self::Error> {
        match verifier.key_type() {
            // selfsign::KeyType::Secp256k1 => {
            //     unimplemented!("blah");
            // }
            // selfsign::KeyType::P256 => {
            //     unimplemented!("blah");
            // }
            // selfsign::KeyType::P384 => {
            //     unimplemented!("blah");
            // }
            // selfsign::KeyType::P521 => {
            //     unimplemented!("blah");
            // }
            _ => Err(Error::Unrecognized("EC curve")),
        }
    }
}
