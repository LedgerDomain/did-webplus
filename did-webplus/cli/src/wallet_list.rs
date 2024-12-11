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
        let wallet_uuid_o = self.wallet_args.get_wallet_uuid_o()?;
        let wallet_storage = self.wallet_args.get_wallet_storage().await?;

        use did_webplus_doc_store::DIDDocStorage;
        use did_webplus_wallet_store::WalletStorage;
        let mut transaction = wallet_storage.begin_transaction(None).await?;
        let wallet_record_v = wallet_storage
            .get_wallets(
                &mut transaction,
                &did_webplus_wallet_store::WalletRecordFilter {
                    wallet_uuid_o,
                    ..Default::default()
                },
            )
            .await?
            .into_iter()
            .map(|(_ctx, wallet_record)| wallet_record)
            .collect::<Vec<_>>();
        wallet_storage.commit_transaction(transaction).await?;

        serde_json::to_writer(std::io::stdout(), &wallet_record_v)?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
