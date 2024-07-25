use crate::Result;
use did_webplus::{DIDStr, ParsedDIDWithQuery};

#[async_trait::async_trait]
pub trait Wallet {
    /// Create a new (set of) private key(s), create a root DID document containing the corresponding public key(s),
    /// and send the DID document to the specified VDR.  This DID is now a locally-controlled DID.  Returns the
    /// DIDWithQuery corresponding to the updated DID doc (i.e. the DID with selfHash and versionId query params; in
    /// this case, the query selfHash matches the DID doc selfHash, and the query versionId is 0).
    async fn create_did(&self, vdr_did_create_endpoint: &str) -> Result<ParsedDIDWithQuery>;
    /// Retrieve all DID document updates for the given DID from the VDR, verify them, and store the latest DID document.
    // TODO: Figure out how to update any other local doc stores.
    async fn fetch_did(&self, did: &DIDStr, vdr_scheme: &'static str) -> Result<()>;
    /// Retrieve the latest DID document from the VDR, rotate the key(s) of a locally-controlled DID, update
    /// the DID document, and send the updated DID document to the VDR.  The initial retrieval step is necessary
    /// only if there are other wallets that control this DID and that have updated the DID document since the last
    /// time this wallet updated the DID document.  Returns the DIDWithQuery corresponding to the updated DID doc
    /// (i.e. the DID with selfHash and versionId query params).
    async fn update_did(
        &self,
        did: &DIDStr,
        vdr_scheme: &'static str,
    ) -> Result<ParsedDIDWithQuery>;
}
