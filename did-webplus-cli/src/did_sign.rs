use crate::Result;

/// Produce a signature using an appropriate key from a locally-controlled DID.
#[derive(clap::Parser)]
pub struct DIDSign {
    // TODO
}

impl DIDSign {
    pub async fn handle(self) -> Result<()> {
        unimplemented!();
    }
}
