#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid DID microledger: {0}")]
    InvalidDIDMicroledger(&'static str),
    #[error("Invalid did:webplus create operation: {0}")]
    InvalidDIDWebplusCreateOperation(&'static str),
    #[error("Invalid did:webplus update operation: {0}")]
    InvalidDIDWebplusUpdateOperation(&'static str),
    #[error("Malformed: {0}")]
    Malformed(&'static str),
    #[error("Malformed {0} method: {1}")]
    MalformedKeyFragment(&'static str, &'static str),
    #[error("Not found: {0}")]
    NotFound(&'static str),
}
