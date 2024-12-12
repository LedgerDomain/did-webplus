use crate::{NewlineArgs, Result, WalletArgs};

/// List wallets within the specified wallet database, optionally filtering using --wallet-uuid.  The output
/// is a JSON array of wallet records.
#[derive(clap::Parser)]
pub struct WalletList {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl WalletList {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let wallet_uuid_o = self.wallet_args.get_wallet_uuid_o()?;
        let wallet_storage = self.wallet_args.get_wallet_storage().await?;
        let wallet_record_filter = did_webplus_wallet_store::WalletRecordFilter {
            wallet_uuid_o,
            ..Default::default()
        };

        // Do the processing
        let wallet_record_v =
            did_webplus_cli_lib::wallet_list(wallet_storage, &wallet_record_filter).await?;

        // Print the wallet records as JSON, then optional newline.
        serde_json::to_writer(std::io::stdout(), &wallet_record_v)?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
