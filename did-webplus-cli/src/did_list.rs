use crate::{DIDListLocal, DIDListResolved, Result};

/// DID listing operations.
#[derive(clap::Subcommand)]
pub enum DIDList {
    Local(DIDListLocal),
    Resolved(DIDListResolved),
}

impl DIDList {
    pub async fn handle(self) -> Result<()> {
        match self {
            DIDList::Local(x) => x.handle().await,
            DIDList::Resolved(x) => x.handle().await,
        }
    }
}
