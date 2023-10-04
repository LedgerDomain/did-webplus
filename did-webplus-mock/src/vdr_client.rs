use did_webplus::{DIDDocument, Error, DID};

/// This trait represents the client side of the interaction with the VDR.
// TODO: Maybe make a method for retrieving the parameters that the client should use to
// construct the root DID document (e.g. the path components of the DID, which may be
// dictated by the VDR).
pub trait VDRClient {
    fn create_did(&self, root_did_document: DIDDocument) -> Result<DID, Error>;
    fn update_did(&self, new_did_document: DIDDocument) -> Result<(), Error>;
}
