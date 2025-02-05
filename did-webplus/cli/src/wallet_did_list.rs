use crate::{NewlineArgs, Result, WalletArgs};

/// List all controlled DIDs in the specified wallet(s) in the wallet database.  If --wallet-uuid is specified,
/// then list only DIDs that are controlled by that wallet.
#[derive(clap::Parser)]
pub struct WalletDIDList {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    /// Optionally limit results to the given DID.  This is useful e.g. for getting the fully qualified form
    /// of the DID as it is currently controlled by the wallet.
    #[arg(name = "did", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus_core::DID>,
    /// Print the DIDs in fully qualified form (i.e. including the selfHash and versionId query parameters).
    #[arg(short, long)]
    pub fully_qualified: bool,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl WalletDIDList {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let wallet = self.wallet_args.open_wallet().await?;

        // Do the processing
        let controlled_did_v =
            did_webplus_cli_lib::wallet_did_list(&wallet, self.did_o.as_deref()).await?;

        // Print the DIDs as JSON (either in fully-qualified form or as base DIDs), then optional newline.
        if self.fully_qualified {
            serde_json::to_writer(std::io::stdout(), &controlled_did_v)?;
        } else {
            let did_v = controlled_did_v
                .iter()
                .map(|controlled_did| controlled_did.did())
                .collect::<Vec<_>>();
            serde_json::to_writer(std::io::stdout(), &did_v)?;
        }
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
