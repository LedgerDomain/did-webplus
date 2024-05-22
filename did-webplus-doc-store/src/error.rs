use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Already exists: {0}")]
    AlreadyExists(Cow<'static, str>),
    #[error("Internal error: {0}")]
    InternalError(Cow<'static, str>),
    #[error("Invalid DID document: {0}")]
    InvalidDIDDocument(#[from] did_webplus::Error),
    #[error("Not found: {0}")]
    NotFound(Cow<'static, str>),
    #[error("Record corruption detected: {0}; Stored record self-hash was {1}")]
    RecordCorruption(Cow<'static, str>, Cow<'static, str>),
    #[error("Storage error: {0}")]
    StorageError(Cow<'static, str>),
}
