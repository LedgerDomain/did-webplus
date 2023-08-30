use crate::{DIDWebplus, Error, KeyMaterial};

// TODO: Maybe make this an enum called DIDDocument instead for static dispatch.
pub trait DIDDocumentTrait {
    fn id(&self) -> &DIDWebplus;
    fn said(&self) -> &said::SelfAddressingIdentifier;
    fn prev_did_document_said_o(&self) -> Option<&said::SelfAddressingIdentifier>;
    fn valid_from(&self) -> &chrono::DateTime<chrono::Utc>;
    fn version_id(&self) -> u32;
    fn key_material(&self) -> &KeyMaterial;
    /// This assumes that the specified prev DID document (if any) has already been verified, so
    /// that this call doesn't recurse fully, and only performs one level of verification for the
    /// DID's microledger.
    fn verify(
        &self,
        expected_prev_did_document_bo: Option<Box<&dyn DIDDocumentTrait>>,
    ) -> Result<(), Error>;
    /// Convenience method for calling self.verify(None).
    fn verify_root(&self) -> Result<(), Error> {
        self.verify(None)
    }
    /// Convenience method for calling self.verify(Some(expected_prev_did_document_b)).
    fn verify_non_root(
        &self,
        expected_prev_did_document_b: Box<&dyn DIDDocumentTrait>,
    ) -> Result<(), Error> {
        self.verify(Some(expected_prev_did_document_b))
    }
}
