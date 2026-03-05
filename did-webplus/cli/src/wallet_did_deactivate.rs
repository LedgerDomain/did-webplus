use crate::{
    HTTPHeadersArgs, HTTPSchemeOverrideArgs, NewlineArgs, Result, WalletArgs,
    get_uniquely_determinable_did,
};
use std::io::Write;

/// Deactivate a DID that is controlled by the specified wallet by sending the deactivated DID
/// document to its VDR.  If no --wallet-uuid argument is specified, then there must only be one
/// wallet in the database, and that wallet will be used.  If there is more than one wallet in the
/// database, the --wallet-uuid argument must be specified.
#[derive(clap::Parser)]
pub struct WalletDIDDeactivate {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    #[command(flatten)]
    pub http_headers_args: HTTPHeadersArgs,
    #[command(flatten)]
    pub http_scheme_override_args: HTTPSchemeOverrideArgs,
    /// Specify the DID to be deactivated.  If not specified and there is exactly one DID controlled
    /// by the wallet, then that DID will be used -- it is uniquely determinable.  If there is no
    /// uniquely determinable DID, then an error will be returned.
    #[arg(name = "did", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus_core::DID>,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
    /// DID deactivate is an irreversible action.  This argument is used to prevent accidental
    /// DID deactivation by requiring the user to explicitly confirm the action by providing the
    /// argument `--confirm THIS-IS-IRREVERSIBLE`.  If not provided or not equal to that verbatim
    /// text, an error will be returned.
    #[arg(name = "confirm", long, value_name = "TEXT")]
    pub confirm_o: Option<String>,
}

impl WalletDIDDeactivate {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        if !matches!(self.confirm_o.as_deref(), Some("THIS-IS-IRREVERSIBLE")) {
            anyhow::bail!(
                "DID deactivate is an irreversible action, and a confirmation is required.  The argument `--confirm THIS-IS-IRREVERSIBLE` is used to prevent accidental DID deactivation via explicit confirmation.  If not provided or not equal to that verbatim text, an error will be returned."
            );
        }
        let wallet = self.wallet_args.open_wallet().await?;
        let did = get_uniquely_determinable_did(&wallet, self.did_o).await?;
        let http_options_o = Some(did_webplus_core::HTTPOptions {
            http_headers_for: self.http_headers_args.http_headers_for.clone(),
            http_scheme_override: self.http_scheme_override_args.http_scheme_override.clone(),
        });

        // Do the processing
        let deactivated_did =
            did_webplus_cli_lib::wallet_did_deactivate(&wallet, &did, http_options_o.as_ref())
                .await?;

        // Print the fully-qualified form of the deactivated DID and optional newline.
        std::io::stdout().write_all(deactivated_did.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
