use crate::{DIDDocument, Error};

/// Trait defining the DID microledger data model.  The trait is defined generally enough so that
/// it could be implemented for a Microledger held entirely in memory, or one stored in a database.
// TODO: Need an async version for a sqlx-backed implementation.
pub trait MicroledgerMutView<'v> {
    /// This verifies that the given non-root DID document is a valid update, and then will append it to
    /// the microledger.
    fn update(&mut self, non_root_did_document: DIDDocument) -> Result<(), Error>;
}
