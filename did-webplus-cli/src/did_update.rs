use crate::Result;

/// Update a locally-controlled DID by rotating its current keys sending the updated DID document to its VDR.
#[derive(clap::Parser)]
pub struct DIDUpdate {
    // TODO
}

impl DIDUpdate {
    pub async fn handle(self) -> Result<()> {
        unimplemented!();
    }
}
