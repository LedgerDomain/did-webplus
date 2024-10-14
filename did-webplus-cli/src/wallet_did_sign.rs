use crate::{Result, WalletDIDSignJWS};

/// Wallet DID signing operations.
#[derive(clap::Subcommand)]
pub enum WalletDIDSign {
    JWS(WalletDIDSignJWS),
}

impl WalletDIDSign {
    pub async fn handle(self) -> Result<()> {
        match self {
            WalletDIDSign::JWS(x) => x.handle().await,
        }
    }
}
