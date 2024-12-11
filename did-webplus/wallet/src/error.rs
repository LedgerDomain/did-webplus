use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DIDDocStoreError(did_webplus_doc_store::Error),
    #[error("Failed to fetch DID updates: {0}")]
    DIDFetchError(Cow<'static, str>),
    #[error("Wallet does not control DID: {0}")]
    DIDNotControlledByWallet(Cow<'static, str>),
    #[error(transparent)]
    DIDWebplusError(did_webplus_core::Error),
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
    #[error("Multiple locally controlled verification methods found: {0}")]
    MultipleLocallyControlledVerificationMethodsFound(Cow<'static, str>),
    #[error("Multiple suitable priv key found: {0}")]
    MultipleSuitablePrivKeysFound(Cow<'static, str>),
    #[error("Multiple controlled DIDs found: {0}")]
    MultipleControlledDIDsFound(Cow<'static, str>),
    #[error("No controlled DID found: {0}")]
    NoControlledDIDFound(Cow<'static, str>),
    #[error("No locally controlled verification method found: {0}")]
    NoLocallyControlledVerificationMethodFound(Cow<'static, str>),
    #[error("Not found: {0}")]
    NotFound(Cow<'static, str>),
    #[error("No suitable priv key found: {0}")]
    NoSuitablePrivKeyFound(Cow<'static, str>),
    #[error("No uniquely determinable controlled DID found: {0}")]
    NoUniquelyDeterminableControlledDIDFound(Cow<'static, str>),
    #[error(transparent)]
    WalletStorageError(did_webplus_wallet_store::Error),
}

// TODO: Probably derive these

impl From<did_webplus_core::Error> for Error {
    fn from(e: did_webplus_core::Error) -> Self {
        Self::DIDWebplusError(e)
    }
}

impl From<did_webplus_doc_store::Error> for Error {
    fn from(e: did_webplus_doc_store::Error) -> Self {
        Self::DIDDocStoreError(e)
    }
}

impl From<did_webplus_wallet_store::Error> for Error {
    fn from(e: did_webplus_wallet_store::Error) -> Self {
        Self::WalletStorageError(e)
    }
}
