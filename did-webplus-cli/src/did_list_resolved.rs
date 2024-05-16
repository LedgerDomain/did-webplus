use crate::Result;

/// List DIDs that have been resolved and locally cached.
#[derive(clap::Parser)]
pub struct DIDListResolved {
    // TODO
}

impl DIDListResolved {
    pub async fn handle(self) -> Result<()> {
        unimplemented!();
    }
}
