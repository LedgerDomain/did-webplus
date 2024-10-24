use crate::Result;
use pkcs8::DecodePrivateKey;

#[derive(clap::Args)]
pub struct PrivateKeyFileArgs {
    /// Specify the path of the private key to be used in this operation.
    #[arg(
        env = "DID_WEBPLUS_PRIVATE_KEY_PATH",
        short,
        long,
        value_name = "PATH",
        default_value = "~/.did-webplus/privkey.pem"
    )]
    pub private_key_path: std::path::PathBuf,
}

impl PrivateKeyFileArgs {
    pub fn ensure_file_exists(&self) -> Result<()> {
        anyhow::ensure!(
            self.private_key_path.exists(),
            "Path {:?} specified by --private-key-path does not exist.",
            self.private_key_path
        );
        Ok(())
    }
    pub fn read_private_key_file(&self) -> Result<Box<dyn selfsign::Signer>> {
        for &key_type in selfsign::KEY_TYPE_V {
            match key_type {
                selfsign::KeyType::Ed25519 => {
                    if let Ok(signing_key) =
                        ed25519_dalek::SigningKey::read_pkcs8_pem_file(&self.private_key_path)
                    {
                        return Ok(Box::new(signing_key));
                    }
                }
                selfsign::KeyType::Secp256k1 => {
                    if let Ok(signing_key) =
                        k256::ecdsa::SigningKey::read_pkcs8_pem_file(&self.private_key_path)
                    {
                        return Ok(Box::new(signing_key));
                    }
                }
            }
        }
        anyhow::bail!(
            "Private key at path {:?} was not in a recognized format.",
            self.private_key_path
        );
    }
}
