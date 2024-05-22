use crate::{DIDCreate, DIDKeyExchange, DIDList, DIDResolve, DIDSign, DIDUpdate, Result};

#[derive(clap::Subcommand)]
pub enum DID {
    #[command(subcommand)]
    Resolve(DIDResolve),
    #[command(subcommand)]
    List(DIDList),
    Create(DIDCreate),
    Update(DIDUpdate),
    Sign(DIDSign),
    KeyExchange(DIDKeyExchange),
}

impl DID {
    pub async fn handle(self) -> Result<()> {
        match self {
            DID::Resolve(x) => x.handle().await,
            DID::List(x) => x.handle().await,
            DID::Create(x) => x.handle().await,
            DID::Update(x) => x.handle().await,
            DID::Sign(x) => x.handle().await,
            DID::KeyExchange(x) => x.handle().await,
        }
    }
}
