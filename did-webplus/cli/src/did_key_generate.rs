use crate::{NewlineArgs, PrivateKeyFileArgs, Result};
use std::io::Write;

/// Generate a private key and print the did:key representation of the corresponding public key.  If
/// the path exists already, it will not be overwritten, and this program will return an error.
#[derive(clap::Args)]
pub struct DIDKeyGenerate {
    /// Specify the type of key to be generated.
    #[arg(short, long, value_enum)]
    pub key_type: selfsign::KeyType,
    #[command(flatten)]
    pub private_key_file_args: PrivateKeyFileArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDKeyGenerate {
    pub fn handle(self) -> Result<()> {
        // Handle CLI args and input
        self.private_key_file_args.ensure_file_does_not_exist()?;
        let private_key_path = self.private_key_file_args.private_key_path()?;

        // Do the processing
        let did = did_webplus_cli_lib::did_key_generate_to_pkcs8_pem_file(
            self.key_type,
            &private_key_path,
        )?;

        // Print the did:key representation of the public key corresponding to the generated priv key.
        std::io::stdout().write_all(did.as_bytes()).unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
