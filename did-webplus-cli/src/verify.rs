use crate::{Result, VerifyJWS, VerifyVJSON};

/// Verification operations.
#[derive(clap::Subcommand)]
pub enum Verify {
    JWS(VerifyJWS),
    // JWT(VerifyJWT),
    VJSON(VerifyVJSON),
}

impl Verify {
    pub async fn handle(self) -> Result<()> {
        match self {
            Self::JWS(x) => x.handle().await,
            // Self::JWT(x) => x.handle().await,
            Self::VJSON(x) => x.handle().await,
        }
    }
}
