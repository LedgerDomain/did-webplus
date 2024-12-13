use crate::{JWSPayloadArgs, NewlineArgs, Result, VerificationMethodArgs, WalletArgs};
use std::io::Write;

/// Sign a JWS using the specified DID and specified key purpose from the specified wallet.  The payload
/// for the JWS will be read from stdin.  The JWS will be written to stdout.  If no --wallet-uuid
/// argument is specified, then there must only be one wallet in the database, and that wallet will be
/// used.  If there is more than one wallet in the database, the --wallet-uuid argument must be specified.
#[derive(clap::Parser)]
pub struct WalletDIDSignJWS {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    // TODO: The default behavior should be to fetch the latest DID document for the DID being used to
    // sign before signing, so that the latest version is used, and there should be an argument to disable
    // this behavior, so that it can function fully offline.
    #[command(flatten)]
    pub verification_method_args: VerificationMethodArgs,
    #[command(flatten)]
    pub jws_payload_args: JWSPayloadArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl WalletDIDSignJWS {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let wallet = self.wallet_args.get_wallet().await?;

        // Do the processing
        let jws = did_webplus_cli_lib::wallet_did_sign_jws(
            &mut std::io::stdin(),
            self.jws_payload_args.payload_presence,
            self.jws_payload_args.payload_encoding,
            &wallet,
            self.verification_method_args.controlled_did_o.as_deref(),
            Some(self.verification_method_args.key_purpose),
            self.verification_method_args.key_id_o.as_deref(),
        )
        .await?;

        // Print the JWS and optional newline.
        std::io::stdout().write_all(jws.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
