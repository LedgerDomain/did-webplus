use crate::{get_wallet, Result};

/// Create a DID hosted by a given VDR, which is then controlled by the specified wallet.
#[derive(clap::Parser)]
pub struct WalletDIDCreate {
    /// Specify the URL to the wallet database.  The URL must start with "sqlite://".
    #[arg(
        short = 'u',
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/wallet.db"
    )]
    pub wallet_db_url: String,
    /// Specify the UUID of the wallet within the database to use.  If not specified, then either the
    /// only wallet in the database will be used, or a new wallet will be created.  If there is more
    /// than one wallet in the database, an error will be returned.
    #[arg(name = "wallet-uuid", short = 'w', long, value_name = "UUID")]
    pub wallet_uuid_o: Option<String>,
    /// Specify the URL of the VDR to use for DID creation.  If the URL's scheme is omitted, then "https" will be used.
    /// A scheme of "http" is only allowed if the host is "localhost".  The URL must not contain a query string or fragment.
    #[arg(name = "vdr", short, long, value_name = "URL")]
    pub vdr_did_create_endpoint: url::Url,
}

impl WalletDIDCreate {
    pub async fn handle(self) -> Result<()> {
        let wallet_uuid_o = self
            .wallet_uuid_o
            .map(|wallet_uuid_string| uuid::Uuid::parse_str(&wallet_uuid_string))
            .transpose()?;
        let wallet = get_wallet(&self.wallet_db_url, wallet_uuid_o.as_ref()).await?;
        use did_webplus_wallet::Wallet;
        let created_did = wallet
            .create_did(self.vdr_did_create_endpoint.as_str())
            .await?;
        println!("{}", created_did);
        Ok(())
    }
}
