use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DID Doc store error: {0}")]
    DIDDocStoreError(#[from] did_webplus_doc_store::Error),
    #[error("Malformed: {0}")]
    Malformed(Cow<'static, str>),
    #[error("Not found: {0}")]
    NotFound(Cow<'static, str>),
    #[error("Record corruption detected: {0}")]
    RecordCorruption(Cow<'static, str>),
    #[error("Storage error: {0}")]
    StorageError(Cow<'static, str>),
}

#[cfg(feature = "sqlx")]
impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Self::StorageError(err.to_string().into())
    }
}

impl From<storage_traits::Error> for Error {
    fn from(err: storage_traits::Error) -> Self {
        Self::StorageError(err.to_string().into())
    }
}
