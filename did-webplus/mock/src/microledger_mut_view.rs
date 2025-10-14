/// Trait defining the DID microledger data model.  The trait is defined generally enough so that
/// it could be implemented for a Microledger held entirely in memory, or one stored in a database.
// TODO: This should not need to take `&mut self`, since the view itself is not mutable.
// TODO: Move this into did-webplus-mock, since it's not used anywhere else
pub trait MicroledgerMutView<'v> {
    /// This verifies that the given non-root DID document is a valid update, and then will append it to
    /// the microledger.
    // TODO: Consider making this use Cow<'_, DIDDocument>
    fn update(
        &mut self,
        new_did_document: did_webplus_core::DIDDocument,
    ) -> did_webplus_core::Result<()>;
}
