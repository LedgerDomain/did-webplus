use std::borrow::Cow;

use crate::HTTPError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DIDDocStoreError(did_webplus_doc_store::Error),
    #[error("DID resolution failure: {0}")]
    DIDResolutionFailure(HTTPError),
    #[error("Failed constraint: {0}")]
    FailedConstraint(Cow<'static, str>),
    #[error("Malformed DID query: {0}")]
    MalformedDIDQuery(Cow<'static, str>),
}

impl From<did_webplus_doc_store::Error> for Error {
    fn from(error: did_webplus_doc_store::Error) -> Self {
        Self::DIDDocStoreError(error)
    }
}

impl From<HTTPError> for Error {
    fn from(http_error: HTTPError) -> Self {
        Self::DIDResolutionFailure(http_error)
    }
}
