use crate::{determine_http_scheme, get_uniquely_determinable_did, get_wallet, Result};

/// Update a DID that is controlled by the specified wallet by rotating the DID's current keys
/// and sending the updated DID document to its VDR.
#[derive(clap::Parser)]
pub struct WalletDIDUpdate {
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
    /// Specify the DID to be updated.  If not specified and there is exactly one DID controlled by
    /// the wallet, then that DID will be used -- it is uniquely determinable.  If there is no uniquely
    /// determinable DID, then an error will be returned.
    #[arg(name = "did", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus::DID>,
}

impl WalletDIDUpdate {
    pub async fn handle(self) -> Result<()> {
        let http_scheme = determine_http_scheme();

        let wallet_uuid_o = self
            .wallet_uuid_o
            .map(|wallet_uuid_string| uuid::Uuid::parse_str(&wallet_uuid_string))
            .transpose()?;
        let wallet = get_wallet(&self.wallet_db_url, wallet_uuid_o.as_ref()).await?;

        let did = get_uniquely_determinable_did(&wallet, self.did_o).await?;
        use did_webplus_wallet::Wallet;
        let updated_did = wallet.update_did(&did, http_scheme).await?;
        println!("{}", updated_did);

        Ok(())
    }
}
