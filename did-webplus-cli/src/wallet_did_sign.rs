use crate::{Result, WalletDIDSignJWS, WalletDIDSignVJSON};

/// Signing operations using a specified DID from a specified wallet.
#[derive(clap::Subcommand)]
pub enum WalletDIDSign {
    JWS(WalletDIDSignJWS),
    VJSON(WalletDIDSignVJSON),
}

impl WalletDIDSign {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::JWS(x) => x.handle().await,
            Self::VJSON(x) => x.handle().await,
        }
    }
}
