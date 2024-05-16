use crate::Result;

/// Verify a JWS signed by a did:webplus DID.
#[derive(clap::Parser)]
pub struct VerifyJWS {
    // TODO -- specify resolver options
}

impl VerifyJWS {
    pub async fn handle(self) -> Result<()> {
        // TODO
        unimplemented!();
    }
}
