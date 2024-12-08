use crate::{DIDDocument, Error, MicroledgerMutView};

/// Async version of the trait defining the DID microledger data model.  The trait is defined generally
/// enough so that it could be implemented for a Microledger held entirely in memory, or one stored
/// in a database.
#[async_trait::async_trait]
pub trait MicroledgerMutViewAsync<'v> {
    /// This verifies that the given non-root DID document is a valid update, and then will append it to
    /// the microledger.
    // TODO: Consider making this use Cow<'_, DIDDocument>
    async fn update(&mut self, new_did_document: DIDDocument) -> Result<(), Error>;
}

/// Default implementation for MicroledgerMutViewAsync for any type that implements MicroledgerMutView
/// and Send.  Thus it's preferred to implement the sync version of the trait if at all possible,
/// and then the async version will be automatically derived.
#[async_trait::async_trait]
impl<'v, V: MicroledgerMutView<'v> + Send> MicroledgerMutViewAsync<'v> for V {
    async fn update(&mut self, new_did_document: DIDDocument) -> Result<(), Error> {
        MicroledgerMutView::update(self, new_did_document)
    }
}
