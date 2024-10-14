use crate::{Result, VerifyJWS};

#[derive(clap::Subcommand)]
pub enum Verify {
    JWS(VerifyJWS),
    // JWT(VerifyJWT),
}

impl Verify {
    pub async fn handle(self) -> Result<()> {
        match self {
            Verify::JWS(x) => x.handle().await,
            // Verify::JWT(x) => x.handle().await,
        }
    }
}
