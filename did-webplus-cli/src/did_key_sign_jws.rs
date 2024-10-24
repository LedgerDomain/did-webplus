use crate::{NewlineArgs, PrivateKeyFileArgs, Result};
use std::io::Write;

/// Sign a JWS using the private key from the specified file, where the `did:key` DID method is
/// used to represent the public key.  The payload for the JWS will be read from stdin.  The JWS
/// will be written to stdout.
#[derive(clap::Parser)]
pub struct DIDKeySignJWS {
    #[command(flatten)]
    pub private_key_file_args: PrivateKeyFileArgs,
    /// Specify if the payload is "attached" (meaning included in the JWS itself) or "detached" (meaning
    /// omitted from the JWS itself).
    // TODO: Use enums
    #[arg(long, value_name = "VALUE", default_value = "attached")]
    pub payload: String,
    /// Specify how the payload should be interpreted -- "none" means that the bytes of the payload should
    /// not be base64url-nopad-decoded before processing.  "base64" means that the bytes of the payload
    /// should be base64url-nopad-decoded before processing.
    // TODO: Use enums
    #[arg(long, value_name = "ENCODING", default_value = "base64")]
    pub encoding: String,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDKeySignJWS {
    pub fn handle(self) -> Result<()> {
        let payload_presence = if self.payload.eq_ignore_ascii_case("attached") {
            did_webplus_jws::JWSPayloadPresence::Attached
        } else if self.payload.eq_ignore_ascii_case("detached") {
            did_webplus_jws::JWSPayloadPresence::Detached
        } else {
            anyhow::bail!(
                "Invalid value {:?} for --payload argument; expected \"attached\" or \"detached\"",
                self.payload
            );
        };

        let payload_encoding = if self.encoding.eq_ignore_ascii_case("none") {
            did_webplus_jws::JWSPayloadEncoding::None
        } else if self.encoding.eq_ignore_ascii_case("base64") {
            did_webplus_jws::JWSPayloadEncoding::Base64URL
        } else {
            anyhow::bail!(
                "Invalid value {:?} for --encoding argument; expected \"none\" or \"base64\"",
                self.encoding
            );
        };

        self.private_key_file_args.ensure_file_exists()?;

        let signer_b = self.private_key_file_args.read_private_key_file()?;
        let did_resource =
            did_key::DIDResource::try_from(&signer_b.verifier().to_verifier_bytes())?;

        let jws = did_webplus_jws::JWS::signed(
            did_resource.to_string(),
            &mut std::io::stdin(),
            payload_presence,
            payload_encoding,
            signer_b.as_ref(),
        )?;

        std::io::stdout().write_all(jws.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
