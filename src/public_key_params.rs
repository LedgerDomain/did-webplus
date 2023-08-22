// "kty" of "EC" is used for curves including "secp256k1", "P-256" (which is sometimes also called "secp256r1"),
// "P-384", and "P-521".
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
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

// "kty" of "OKP" is used for curves including "ed25519".
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PublicKeyParamsOKP {
    pub crv: String,
    pub x: String,
}

impl PublicKeyParamsOKP {
    /// Convenience function for creating the PublicKeyParamsOKP for an ed25519 key.
    pub fn ed25519(x: String) -> Self {
        Self {
            crv: "ed25519".into(),
            x,
        }
    }
}

// Note that this will use the "kty" field in serde to determine the variant of the enum.
#[derive(Clone, Debug, serde::Deserialize, derive_more::From, serde::Serialize)]
#[serde(tag = "kty")]
pub enum PublicKeyParams {
    EC(PublicKeyParamsEC),
    OKP(PublicKeyParamsOKP),
}
