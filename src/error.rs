#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Already exists: {0}")]
    AlreadyExists(&'static str),
    #[error("Invalid: {0}")]
    Invalid(&'static str),
    #[error("Invalid DID microledger: {0}")]
    InvalidDIDMicroledger(&'static str),
    #[error("Invalid did:webplus create operation: {0}")]
    InvalidDIDWebplusCreateOperation(&'static str),
    #[error("Invalid did:webplus update operation: {0}")]
    InvalidDIDWebplusUpdateOperation(&'static str),
    #[error("Invalid self-signature or self-hash: {0}")]
    InvalidSelfSignatureOrSelfHash(&'static str),
    #[error("Malformed: {0}")]
    Malformed(&'static str),
    #[error("Malformed {0} method: {1}")]
    MalformedKeyFragment(&'static str, &'static str),
    #[error("Not found: {0}")]
    NotFound(&'static str),
    #[error("Generic error: {0}")]
    Generic(&'static str),
    #[error("Unrecognized: {0}")]
    Unrecognized(&'static str),
    #[error("Unsupported: {0}")]
    Unsupported(&'static str),
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Self::Generic(s)
    }
}
