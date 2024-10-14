use std::io::Write;

use crate::{get_wallet_storage, Result};

/// List all wallets within the specified wallet database.  The output is a JSON array of wallet records.
#[derive(clap::Parser)]
pub struct WalletList {
    /// Specify the URL to the wallet database.  The URL must start with "sqlite://".
    #[arg(
        short = 'u',
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/wallet.db"
    )]
    pub wallet_db_url: String,
    /// Do not print a newline at the end of the output.
    #[arg(short, long)]
    pub no_newline: bool,
}

impl WalletList {
    pub async fn handle(self) -> Result<()> {
        let storage = get_wallet_storage(&self.wallet_db_url).await?;
        use did_webplus_doc_store::DIDDocStorage;
        use did_webplus_wallet_storage::WalletStorage;
        let mut transaction = storage.begin_transaction(None).await?;
        let wallet_record_v = storage
            .get_wallets(
                &mut transaction,
                &did_webplus_wallet_storage::WalletRecordFilter::default(),
            )
            .await?
            .into_iter()
            .map(|(_ctx, wallet_record)| wallet_record)
            .collect::<Vec<_>>();
        transaction.commit().await?;

        serde_json::to_writer(std::io::stdout(), &wallet_record_v)?;
        if !self.no_newline {
            std::io::stdout().write_all(b"\n")?;
        }

        Ok(())
    }
}
