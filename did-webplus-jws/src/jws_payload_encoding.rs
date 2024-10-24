#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JWSPayloadEncoding {
    /// No encoding.
    None,
    /// This really means base64url-no-pad encoding.
    Base64URL,
}
