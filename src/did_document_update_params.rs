use crate::PublicKeySet;

/// did:webplus-specific parameters for creating a non-root DID document in order to update a DID's microledger.
#[derive(Debug)]
pub struct DIDDocumentUpdateParams<'a> {
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
}
