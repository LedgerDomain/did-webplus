use crate::Result;

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
    private_key_path: String,
}

impl PrivateKeyFileArgs {
    pub fn private_key_path(&self) -> Result<std::path::PathBuf> {
        Ok(expanduser::expanduser(&self.private_key_path)?)
    }
    pub fn ensure_file_exists(&self) -> Result<()> {
        let private_key_path = self.private_key_path()?;
        anyhow::ensure!(
            private_key_path.exists(),
            "Path {:?} specified by --private-key-path does not exist.",
            private_key_path
        );
        Ok(())
    }
    pub fn ensure_file_does_not_exist(&self) -> Result<()> {
        let private_key_path = self.private_key_path()?;
        anyhow::ensure!(
            !private_key_path.exists(),
            "Path {:?} specified by --private-key-path already exists.",
            private_key_path
        );
        Ok(())
    }
    pub fn read_private_key_file(&self) -> Result<Box<dyn selfsign::Signer>> {
        let private_key_path = self.private_key_path()?;
        did_webplus_cli_lib::private_key_read_from_pkcs8_pem_file(&private_key_path)
    }
}
