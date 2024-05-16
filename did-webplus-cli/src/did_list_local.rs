use crate::Result;

/// List locally-controlled DIDs.
#[derive(clap::Parser)]
pub struct DIDListLocal {
    // TODO
}

impl DIDListLocal {
    pub async fn handle(self) -> Result<()> {
        unimplemented!();
    }
}
