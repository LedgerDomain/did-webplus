use crate::{DIDList, DIDResolve, Result};

/// DID operations that don't require a wallet.  These are operations typically associated
/// with verifying parties that don't necessarily control a DID.
#[derive(clap::Subcommand)]
pub enum DID {
    List(DIDList),
    #[command(subcommand)]
    Resolve(DIDResolve),
}

impl DID {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::List(x) => x.handle().await,
            Self::Resolve(x) => x.handle().await,
        }
    }
}
