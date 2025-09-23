// TODO: Use Cow<'static, str>
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Already exists: {0}")]
    AlreadyExists(&'static str),
    #[error("Invalid: {0}")]
    Invalid(&'static str),
    #[error("Invalid DID microledger: {0}")]
    InvalidDIDMicroledger(&'static str),
    #[error("Invalid did:webplus create operation: {0}")]
    InvalidDIDCreateOperation(&'static str),
    #[error("Invalid did:webplus update operation: {0}")]
    InvalidDIDUpdateOperation(&'static str),
    #[error("Invalid self-signature or self-hash: {0}")]
    InvalidSelfSignatureOrSelfHash(&'static str),
    #[error("Malformed: {0}")]
    Malformed(&'static str),
    #[error("Malformed {0} method: {1}")]
    MalformedKeyId(&'static str, &'static str),
    #[error("Not found: {0}")]
    NotFound(&'static str),
    #[error("Generic error: {0}")]
    Generic(&'static str),
    #[error("MBC error: {0}")]
    MBCError(mbx::Error),
    #[error("Self-hash error: {0}")]
    SelfHashError(selfhash::Error),
    #[error("Signature error: {0}")]
    SignatureError(signature_dyn::Error),
    #[error("Serialization error: {0}")]
    Serialization(&'static str),
    #[error("Signing error: {0}")]
    SigningError(&'static str),
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

impl From<mbx::Error> for Error {
    fn from(e: mbx::Error) -> Self {
        Self::MBCError(e)
    }
}

impl From<selfhash::Error> for Error {
    fn from(e: selfhash::Error) -> Self {
        Self::SelfHashError(e)
    }
}

impl From<signature_dyn::Error> for Error {
    fn from(e: signature_dyn::Error) -> Self {
        Self::SignatureError(e)
    }
}
