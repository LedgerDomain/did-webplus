use crate::{DIDWebplus, KeyMaterial};

/// Parameters needed for creating a root DID document.
#[derive(Clone, Debug)]
pub struct RootDIDDocumentParams {
    // Should have the form "did:webplus:host.com:<placeholder>".
    pub did_webplus_with_placeholder: DIDWebplus,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    pub key_material: KeyMaterial,
}
