use crate::{Result, VerifyJWS, WalletDIDSignJWS};

/// JWS-related operations (JSON Web Signature).
#[derive(clap::Subcommand)]
pub enum JWS {
    Sign(WalletDIDSignJWS),
    Verify(VerifyJWS),
    // TODO: There could be a did:key form of sign
}

impl JWS {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::Sign(x) => x.handle().await,
            Self::Verify(x) => x.handle().await,
        }
    }
}
