use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DIDDocStoreError(did_webplus_doc_store::Error),
    #[error("Failed to fetch DID updates: {0}")]
    DIDFetchError(Cow<'static, str>),
    #[error(transparent)]
    DIDWebplusError(did_webplus::Error),
    // TODO: is there an HTTP status code to include here?
    #[error("HTTP operation status: {0}")]
    HTTPOperationStatus(Cow<'static, str>),
    // TODO: is there an HTTP status code to include here?
    #[error("HTTP request error: {0}")]
    HTTPRequestError(Cow<'static, str>),
    #[error("Invalid VDR DID Create URL: {0}")]
    InvalidVDRDIDCreateURL(Cow<'static, str>),
    #[error("Invalid VDR DID Update URL: {0}")]
    InvalidVDRDIDUpdateURL(Cow<'static, str>),
    #[error("Malformed: {0}")]
    Malformed(Cow<'static, str>),
    #[error("Not found: {0}")]
    NotFound(Cow<'static, str>),
    #[error("No suitable priv key found: {0}")]
    NoSuitablePrivKeyFound(Cow<'static, str>),
    #[error(transparent)]
    WalletStorageError(did_webplus_wallet_storage::Error),
}

// TODO: Probably derive these

impl From<did_webplus::Error> for Error {
    fn from(e: did_webplus::Error) -> Self {
        Self::DIDWebplusError(e)
    }
}

impl From<did_webplus_doc_store::Error> for Error {
    fn from(e: did_webplus_doc_store::Error) -> Self {
        Self::DIDDocStoreError(e)
    }
}

impl From<did_webplus_wallet_storage::Error> for Error {
    fn from(e: did_webplus_wallet_storage::Error) -> Self {
        Self::WalletStorageError(e)
    }
}
