use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Already exists: {0}")]
    AlreadyExists(Cow<'static, str>),
    #[error("Internal error: {0}")]
    InternalError(Cow<'static, str>),
    #[error("Invalid VJSON: {0}")]
    InvalidVJSON(Cow<'static, str>),
    #[error("Malformed: {0}")]
    Malformed(Cow<'static, str>),
    #[error("Not found: {0}")]
    NotFound(Cow<'static, str>),
    #[error("Record corruption detected: {0}")]
    RecordCorruption(Cow<'static, str>),
    #[error("Storage error: {0}")]
    StorageError(Cow<'static, str>),
    #[error("Unsupported: {0}")]
    Unsupported(Cow<'static, str>),
    #[error(transparent)]
    VJSONCoreError(#[from] vjson_core::Error),
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

pub fn error_already_exists<E: std::fmt::Display>(e: E) -> Error {
    Error::AlreadyExists(e.to_string().into())
}

pub fn error_internal_error<E: std::fmt::Display>(e: E) -> Error {
    Error::InternalError(e.to_string().into())
}

pub fn error_invalid_vjson<E: std::fmt::Display>(e: E) -> Error {
    Error::InvalidVJSON(e.to_string().into())
}

pub fn error_malformed<E: std::fmt::Display>(e: E) -> Error {
    Error::Malformed(e.to_string().into())
}

pub fn error_not_found<E: std::fmt::Display>(e: E) -> Error {
    Error::NotFound(e.to_string().into())
}

pub fn error_record_corruption<E: std::fmt::Display>(e: E) -> Error {
    Error::RecordCorruption(e.to_string().into())
}

pub fn error_storage_error<E: std::fmt::Display>(e: E) -> Error {
    Error::StorageError(e.to_string().into())
}
