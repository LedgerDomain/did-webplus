use crate::HTTPError;
use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DIDDocStoreError(#[from] did_webplus_doc_store::Error),
    #[error("DID resolution failure: {0}")]
    DIDResolutionFailure(HTTPError),
    #[error("Failed constraint: {0}")]
    FailedConstraint(Cow<'static, str>),
    #[error("Generic error: {0}")]
    GenericError(Cow<'static, str>),
    #[error("Invalid verifier: {0}")]
    InvalidVerifier(Cow<'static, str>),
    #[error("Malformed DID document: {0}")]
    MalformedDIDDocument(Cow<'static, str>),
    #[error("Malformed DID query: {0}")]
    MalformedDIDQuery(Cow<'static, str>),
    #[error("Malformed VDG host: {0}")]
    MalformedVDGHost(Cow<'static, str>),
    #[error(transparent)]
    StorageError(#[from] storage_traits::Error),
}

impl From<HTTPError> for Error {
    fn from(http_error: HTTPError) -> Self {
        Self::DIDResolutionFailure(http_error)
    }
}
