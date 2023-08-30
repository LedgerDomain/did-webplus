use crate::{DIDWebplus, KeyMaterial};

// TODO: Maybe make this an enum called DIDDocument instead for static dispatch.
pub trait DIDDocumentTrait {
    fn id(&self) -> &DIDWebplus;
    fn said(&self) -> &said::SelfAddressingIdentifier;
    fn prev_did_document_said_o(&self) -> Option<&said::SelfAddressingIdentifier>;
    fn valid_from(&self) -> &chrono::DateTime<chrono::Utc>;
    fn version_id(&self) -> u32;
    fn key_material(&self) -> &KeyMaterial;
}
