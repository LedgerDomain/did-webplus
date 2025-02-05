use crate::{get_uniquely_determinable_did, HTTPSchemeArgs, NewlineArgs, Result, WalletArgs};
use std::io::Write;

/// Update a DID that is controlled by the specified wallet by rotating the DID's current keys and
/// sending the updated DID document to its VDR.  If no --wallet-uuid argument is specified, then
/// there must only be one wallet in the database, and that wallet will be used.  If there is more
/// than one wallet in the database, the --wallet-uuid argument must be specified.
#[derive(clap::Parser)]
pub struct WalletDIDUpdate {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    #[command(flatten)]
    pub http_scheme_args: HTTPSchemeArgs,
    /// Specify the DID to be updated.  If not specified and there is exactly one DID controlled by
    /// the wallet, then that DID will be used -- it is uniquely determinable.  If there is no uniquely
    /// determinable DID, then an error will be returned.
    #[arg(name = "did", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus_core::DID>,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl WalletDIDUpdate {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let wallet = self.wallet_args.open_wallet().await?;
        let did = get_uniquely_determinable_did(&wallet, self.did_o).await?;
        let vdr_scheme = self.http_scheme_args.determine_http_scheme();

        // Do the processing
        let updated_did = did_webplus_cli_lib::wallet_did_update(&wallet, &did, vdr_scheme).await?;

        // Print the fully-qualified form of the updated DID and optional newline.
        std::io::stdout().write_all(updated_did.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
