/// Specifies the JWS header "alg" and "crv" fields for a signature algorithm.
/// See <https://www.rfc-editor.org/rfc/rfc7518#page-6> and <https://www.rfc-editor.org/rfc/rfc8037#page-4>
/// for more information.
pub trait JOSEAlgorithmT {
    /// The JWS "alg" field.  For example, "ES256" corresponds to P-256 keys, "ES256K"
    /// corresponds to secp256k1 keys, "EdDSA" corresponds to Ed25519 and Ed448 keys, etc.
    fn alg(&self) -> String;
    /// "EdDSA" algorithms require a "crv" field to fully specify the algorithm.
    /// Valid values are "Ed25519" and "Ed448".
    fn crv_o(&self) -> Option<String>;
}

#[cfg(feature = "ed25519-dalek")]
impl JOSEAlgorithmT for ed25519_dalek::SigningKey {
    fn alg(&self) -> String {
        "EdDSA".to_string()
    }
    fn crv_o(&self) -> Option<String> {
        Some("Ed25519".to_string())
    }
}

#[cfg(feature = "ed25519-dalek")]
impl JOSEAlgorithmT for ed25519_dalek::VerifyingKey {
    fn alg(&self) -> String {
        "EdDSA".to_string()
    }
    fn crv_o(&self) -> Option<String> {
        Some("Ed25519".to_string())
    }
}

#[cfg(feature = "k256")]
impl JOSEAlgorithmT for k256::ecdsa::SigningKey {
    fn alg(&self) -> String {
        "ES256K".to_string()
    }
    fn crv_o(&self) -> Option<String> {
        None
    }
}

#[cfg(feature = "k256")]
impl JOSEAlgorithmT for k256::ecdsa::VerifyingKey {
    fn alg(&self) -> String {
        "ES256K".to_string()
    }
    fn crv_o(&self) -> Option<String> {
        None
    }
}

#[cfg(feature = "p256")]
impl JOSEAlgorithmT for p256::ecdsa::SigningKey {
    fn alg(&self) -> String {
        "ES256".to_string()
    }
    fn crv_o(&self) -> Option<String> {
        None
    }
}

#[cfg(feature = "p256")]
impl JOSEAlgorithmT for p256::ecdsa::VerifyingKey {
    fn alg(&self) -> String {
        "ES256".to_string()
    }
    fn crv_o(&self) -> Option<String> {
        None
    }
}
