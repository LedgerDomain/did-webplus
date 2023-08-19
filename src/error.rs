#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Malformed: {0}")]
    Malformed(&'static str),
    #[error("Invalid DID microledger: {0}")]
    InvalidDIDMicroledger(&'static str),
    #[error("Invalid did:webplus create operation: {0}")]
    InvalidDIDWebplusCreateOperation(&'static str),
    #[error("Invalid did:webplus update operation: {0}")]
    InvalidDIDWebplusUpdateOperation(&'static str),
    #[error("Not found: {0}")]
    NotFound(&'static str),
}
