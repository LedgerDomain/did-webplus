use crate::{Result, WalletDIDCreate, WalletDIDList, WalletDIDSign, WalletDIDUpdate};

/// Wallet DID operations.
#[derive(clap::Subcommand)]
pub enum WalletDID {
    Create(WalletDIDCreate),
    List(WalletDIDList),
    #[command(subcommand)]
    Sign(WalletDIDSign),
    Update(WalletDIDUpdate),
}

impl WalletDID {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::Create(x) => x.handle().await,
            Self::List(x) => x.handle().await,
            Self::Sign(x) => x.handle().await,
            Self::Update(x) => x.handle().await,
        }
    }
}
