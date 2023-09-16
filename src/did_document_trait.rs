use crate::{DIDWebplus, Error, PublicKeyMaterial};

pub trait DIDDocumentTrait: std::fmt::Debug + selfsign::SelfSignable {
    fn id(&self) -> &DIDWebplus;
    fn self_signature(&self) -> &selfsign::KERISignature<'static>;
    fn prev_did_document_self_signature_o(&self) -> Option<&selfsign::KERISignature<'static>>;
    fn valid_from(&self) -> &chrono::DateTime<chrono::Utc>;
    fn version_id(&self) -> u32;
    fn public_key_material(&self) -> &PublicKeyMaterial;
    /// This assumes that the specified prev DID document (if any) has already been verified, so
    /// that this call doesn't recurse fully, and only performs one level of verification for the
    /// DID's microledger.
    fn verify_nonrecursive(
        &self,
        expected_prev_did_document_bo: Option<Box<&dyn DIDDocumentTrait>>,
    ) -> Result<&selfsign::KERISignature<'static>, Error>;
    /// Convenience method for calling self.verify(None).
    fn verify_root(&self) -> Result<&selfsign::KERISignature<'static>, Error> {
        self.verify_nonrecursive(None)
    }
    /// Convenience method for calling self.verify(Some(expected_prev_did_document_b)).
    fn verify_non_root_nonrecursive(
        &self,
        expected_prev_did_document_b: Box<&dyn DIDDocumentTrait>,
    ) -> Result<&selfsign::KERISignature<'static>, Error> {
        self.verify_nonrecursive(Some(expected_prev_did_document_b))
    }
    // TEMP HACK
    fn to_json_pretty(&self) -> String;
}
