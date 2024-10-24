use crate::{NewlineArgs, PrivateKeyFileArgs, Result};
use std::io::Write;

/// Print to stdout the `did:key` representation of the public key corresponding to the specified private key.
#[derive(clap::Args)]
pub struct DIDKeyFromPrivate {
    #[command(flatten)]
    pub private_key_file_args: PrivateKeyFileArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDKeyFromPrivate {
    pub fn handle(self) -> Result<()> {
        self.private_key_file_args.ensure_file_exists()?;

        let signer_b = self.private_key_file_args.read_private_key_file()?;
        let did = did_key::DID::try_from(&signer_b.verifier().to_verifier_bytes())?;

        // Print the did:key value (i.e. pub key) of the read priv key.
        std::io::stdout().write(did.as_bytes()).unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
