use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Already exists: {0}")]
    AlreadyExists(Cow<'static, str>),
    #[error("Invalid: {0}")]
    Invalid(Cow<'static, str>),
    #[error("Invalid DID microledger: {0}")]
    InvalidDIDMicroledger(Cow<'static, str>),
    #[error("Invalid did:webplus create operation: {0}")]
    InvalidDIDCreateOperation(Cow<'static, str>),
    #[error("Invalid did:webplus update operation: {0}")]
    InvalidDIDUpdateOperation(Cow<'static, str>),
    #[error("Malformed: {0}")]
    Malformed(Cow<'static, str>),
    #[error("Malformed {0} method: {1}")]
    MalformedKeyId(Cow<'static, str>, Cow<'static, str>),
    #[error("Not found: {0}")]
    NotFound(Cow<'static, str>),
    #[error("Generic error: {0}")]
    Generic(Cow<'static, str>),
    #[error("MBC error: {0}")]
    MBCError(mbx::Error),
    #[error("Self-hash error: {0}")]
    SelfHashError(selfhash::Error),
    #[error("Signature error: {0}")]
    SignatureError(signature_dyn::Error),
    #[error("Serialization error: {0}")]
    Serialization(Cow<'static, str>),
    #[error("Signing error: {0}")]
    SigningError(Cow<'static, str>),
    #[error("Unrecognized: {0}")]
    Unrecognized(Cow<'static, str>),
    #[error("Unsupported: {0}")]
    Unsupported(Cow<'static, str>),
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Self::Generic(Cow::Borrowed(s))
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::Generic(Cow::Owned(s))
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
