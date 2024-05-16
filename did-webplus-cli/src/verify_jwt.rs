use crate::Result;

/// Verify a JWT signed by a did:webplus DID.
#[derive(clap::Parser)]
pub struct VerifyJWT {
    // TODO -- specify resolver options
}

impl VerifyJWT {
    pub async fn handle(self) -> Result<()> {
        // TODO
        unimplemented!();
    }
}
