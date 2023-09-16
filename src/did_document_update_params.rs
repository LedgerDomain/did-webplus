use crate::PublicKeySet;

/// Params for constructing a non-root DID document specific for did:webplus.
#[derive(Debug)]
pub struct DIDDocumentUpdateParams<'a> {
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
}
