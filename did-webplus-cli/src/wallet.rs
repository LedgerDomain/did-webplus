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
            Wallet::DID(x) => x.handle().await,
            // Wallet::KeyExchange(x) => x.handle().await,
            Wallet::List(x) => x.handle().await,
            // Wallet::Sign(x) => x.handle().await,
        }
    }
}
