use crate::{Result, VJSONSelfHash, VerifyVJSON, WalletDIDSignVJSON};

/// VJSON-related operations (Verifiable JSON).
#[derive(clap::Subcommand)]
pub enum VJSON {
    SelfHash(VJSONSelfHash),
    Sign(WalletDIDSignVJSON),
    Verify(VerifyVJSON),
    // TODO: There could be a did:key form of sign
}

impl VJSON {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::SelfHash(x) => x.handle(),
            Self::Sign(x) => x.handle().await,
            Self::Verify(x) => x.handle().await,
        }
    }
}
