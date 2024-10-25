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

        let storage = self.wallet_args.get_wallet_storage().await?;
        use did_webplus_doc_store::DIDDocStorage;
        use did_webplus_wallet_storage::WalletStorage;
        let mut transaction = storage.begin_transaction(None).await?;
        let wallet_record_v = storage
            .get_wallets(
                &mut transaction,
                &did_webplus_wallet_storage::WalletRecordFilter {
                    wallet_uuid_o,
                    ..Default::default()
                },
            )
            .await?
            .into_iter()
            .map(|(_ctx, wallet_record)| wallet_record)
            .collect::<Vec<_>>();
        transaction.commit().await?;

        serde_json::to_writer(std::io::stdout(), &wallet_record_v)?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
