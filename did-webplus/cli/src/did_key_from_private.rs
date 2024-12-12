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
        // Handle CLI args and input
        self.private_key_file_args.ensure_file_exists()?;
        let signer_b = self.private_key_file_args.read_private_key_file()?;

        // Do the processing
        let did = did_webplus_cli_lib::did_key_from_private(signer_b.as_ref())?;

        // Print the did:key value (i.e. pub key) of the read priv key.
        std::io::stdout().write_all(did.as_bytes()).unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
