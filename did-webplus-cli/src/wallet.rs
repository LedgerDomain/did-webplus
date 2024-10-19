use crate::{Result, WalletDID, WalletList};

/// Wallet operations.
#[derive(clap::Subcommand)]
pub enum Wallet {
    #[command(subcommand)]
    DID(WalletDID),
    // KeyExchange(WalletKeyExchange),
    List(WalletList),
    // #[command(subcommand)]
    // Sign(WalletSign),
}

impl Wallet {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::DID(x) => x.handle().await,
            // Self::KeyExchange(x) => x.handle().await,
            Self::List(x) => x.handle().await,
            // Self::Sign(x) => x.handle().await,
        }
    }
}
