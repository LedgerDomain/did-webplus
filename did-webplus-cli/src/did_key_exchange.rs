use crate::Result;

/// Perform key exchange between a locally-controlled DID and another DID.
#[derive(clap::Parser)]
pub struct DIDKeyExchange {
    // TODO
}

impl DIDKeyExchange {
    pub async fn handle(self) -> Result<()> {
        unimplemented!();
    }
}
