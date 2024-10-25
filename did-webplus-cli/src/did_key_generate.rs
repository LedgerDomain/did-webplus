use std::io::Write;

use crate::{NewlineArgs, PrivateKeyFileArgs, Result};

/// Generate a private key and print the did:key representation of the corresponding public key.  If
/// the path exists already, it will not be overwritten, and this program will return an error.
#[derive(clap::Args)]
pub struct DIDKeyGenerate {
    /// Specify the type of key to be generated.  Must be one of Ed25519, Secp256k1
    // TODO: Figure out how to specify to use std::str::FromStr to parse
    #[arg(short, long)]
    pub key_type: String,
    #[command(flatten)]
    pub private_key_file_args: PrivateKeyFileArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDKeyGenerate {
    pub fn handle(self) -> Result<()> {
        self.private_key_file_args.ensure_file_does_not_exist()?;

        use selfsign::Signer;
        use std::str::FromStr;
        let key_type = selfsign::KeyType::from_str(&self.key_type)
            .map_err(|_| anyhow::anyhow!("invalid --key-type {}", self.key_type))?;
        let did = match key_type {
            selfsign::KeyType::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
                use ed25519_dalek::pkcs8::EncodePrivateKey;
                signing_key
                    .write_pkcs8_pem_file(
                        &self.private_key_file_args.private_key_path()?,
                        Default::default(),
                    )
                    .map_err(|e| {
                        anyhow::anyhow!("failed to write generated key; error was {}", e)
                    })?;
                did_key::DID::try_from(&signing_key.verifier().to_verifier_bytes())?
            }
            selfsign::KeyType::Secp256k1 => {
                let signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
                let did = did_key::DID::try_from(&signing_key.verifier().to_verifier_bytes())?;
                let secret_key = k256::elliptic_curve::SecretKey::from(signing_key);
                use k256::pkcs8::EncodePrivateKey;
                secret_key
                    .write_pkcs8_pem_file(
                        &self.private_key_file_args.private_key_path()?,
                        Default::default(),
                    )
                    .map_err(|e| {
                        anyhow::anyhow!("failed to write generated key; error was {}", e)
                    })?;
                did
            }
        };

        // Print the did:key representation of the public key corresponding to the generated priv key.
        std::io::stdout().write(did.as_bytes()).unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
