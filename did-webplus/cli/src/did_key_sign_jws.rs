use crate::{JWSPayloadArgs, NewlineArgs, PrivateKeyFileArgs, Result};
use std::io::Write;

/// Sign a JWS using the private key from the specified file, where the `did:key` DID method is
/// used to represent the public key.  The payload for the JWS will be read from stdin.  The JWS
/// will be written to stdout.
#[derive(clap::Parser)]
pub struct DIDKeySignJWS {
    #[command(flatten)]
    pub private_key_file_args: PrivateKeyFileArgs,
    #[command(flatten)]
    pub jws_payload_args: JWSPayloadArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDKeySignJWS {
    pub fn handle(self) -> Result<()> {
        // Handle CLI args and input
        self.private_key_file_args.ensure_file_exists()?;
        let signer_b = self.private_key_file_args.read_private_key_file()?;

        // Do the processing
        let jws = did_webplus_cli_lib::did_key_sign_jws(
            &mut std::io::stdin(),
            self.jws_payload_args.payload_presence,
            self.jws_payload_args.payload_encoding,
            signer_b.as_ref(),
        )?;

        // Print the JWS and optional newline.
        std::io::stdout().write_all(jws.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
