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
            WalletDID::Create(x) => x.handle().await,
            WalletDID::List(x) => x.handle().await,
            WalletDID::Sign(x) => x.handle().await,
            WalletDID::Update(x) => x.handle().await,
        }
    }
}
