use crate::{HTTPSchemeOverrideArgs, NewlineArgs, Result, WalletArgs};
use std::io::Write;

/// Create a DID hosted by the specified VDR, which is then controlled by the specified wallet.  If no --wallet-uuid
/// argument is specified, then either the only wallet in the database will be used, or a new wallet will be
/// created.  If there is more than one wallet in the database, the --wallet-uuid argument must be specified.
#[derive(clap::Parser)]
pub struct WalletDIDCreate {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    /// Specify the URL of the VDR to use for DID creation.  If the URL's scheme is omitted, then "https" will be used.
    /// A scheme of "http" is only allowed if the hostname is "localhost".  The URL must not contain a query string or fragment.
    #[arg(name = "vdr", env = "DID_WEBPLUS_VDR", short, long, value_name = "URL")]
    pub vdr_did_create_endpoint: url::Url,
    #[command(flatten)]
    pub http_scheme_override_args: HTTPSchemeOverrideArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl WalletDIDCreate {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let wallet = self.wallet_args.open_wallet().await?;
        let http_scheme_override_o = Some(self.http_scheme_override_args.http_scheme_override);

        // Do the processing
        let created_did = did_webplus_cli_lib::wallet_did_create(
            &wallet,
            self.vdr_did_create_endpoint.as_str(),
            http_scheme_override_o.as_ref(),
        )
        .await?;

        // Print the created DID and optional newline.
        std::io::stdout().write_all(created_did.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
