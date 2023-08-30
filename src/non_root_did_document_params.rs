use crate::KeyMaterial;

/// Params for constructing a non-root DID document specific for did:webplus.
#[derive(Clone, Debug)]
pub struct NonRootDIDDocumentParams {
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub key_material: KeyMaterial,
}
