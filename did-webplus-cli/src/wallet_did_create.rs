use crate::{Result, WalletArgs};

/// Create a DID hosted by the specified VDR, which is then controlled by the specified wallet.  If no --wallet-uuid
/// argument is specified, then either the only wallet in the database will be used, or a new wallet will be
/// created.  If there is more than one wallet in the database, the --wallet-uuid argument must be specified.
#[derive(clap::Parser)]
pub struct WalletDIDCreate {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    /// Specify the URL of the VDR to use for DID creation.  If the URL's scheme is omitted, then "https" will be used.
    /// A scheme of "http" is only allowed if the host is "localhost".  The URL must not contain a query string or fragment.
    #[arg(name = "vdr", env = "DID_WEBPLUS_VDR", short, long, value_name = "URL")]
    pub vdr_did_create_endpoint: url::Url,
}

impl WalletDIDCreate {
    pub async fn handle(self) -> Result<()> {
        let wallet = self.wallet_args.get_wallet().await?;
        use did_webplus_wallet::Wallet;
        let created_did = wallet
            .create_did(self.vdr_did_create_endpoint.as_str())
            .await?;
        println!("{}", created_did);
        Ok(())
    }
}
