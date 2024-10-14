use crate::{get_wallet, Result};

/// List all DIDs controlled by the specified wallet.
#[derive(clap::Parser)]
pub struct WalletDIDList {
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
    // TODO: Consider making this mean "all wallets" if not specified.
    #[arg(name = "wallet-uuid", short = 'w', long, value_name = "UUID")]
    pub wallet_uuid_o: Option<String>,
    /// Optionally limit results to the given DID.  This is useful e.g. for getting the fully qualified form
    /// of the DID as it is currently controlled by the wallet.
    #[arg(name = "did", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus::DID>,
    /// Print the DIDs in fully qualified form (i.e. including the selfHash and versionId query parameters).
    #[arg(short, long)]
    pub fully_qualified: bool,
    /// Do not print a newline at the end of the output.
    #[arg(short, long)]
    pub no_newline: bool,
}

impl WalletDIDList {
    pub async fn handle(self) -> Result<()> {
        let wallet_uuid_o = self
            .wallet_uuid_o
            .map(|wallet_uuid_string| uuid::Uuid::parse_str(&wallet_uuid_string))
            .transpose()?;
        let wallet = get_wallet(&self.wallet_db_url, wallet_uuid_o.as_ref()).await?;
        use did_webplus_wallet::Wallet;
        let controlled_did_v = wallet.get_controlled_dids(self.did_o.as_deref()).await?;
        if self.fully_qualified {
            serde_json::to_writer(std::io::stdout(), &controlled_did_v)?;
        } else {
            let controlled_did_v = controlled_did_v
                .iter()
                .map(|controlled_did| controlled_did.did())
                .collect::<Vec<_>>();
            serde_json::to_writer(std::io::stdout(), &controlled_did_v)?;
        }
        if !self.no_newline {
            use std::io::Write;
            std::io::stdout().write_all(b"\n")?;
        }
        Ok(())
    }
}
