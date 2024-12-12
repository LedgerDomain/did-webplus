use crate::{
    NewlineArgs, Result, VJSONStorageBehaviorArgs, VJSONStoreArgs, VerificationMethodArgs,
    VerifierResolverArgs, WalletArgs,
};

/// Produce VJSON (Verifiable JSON) by signing it using the specified DID and specified key purpose from the
/// specified wallet, then self-hashing it.  The JSON will be read from stdin, and if there is an existing
/// "proofs" field (where the signatures are represented), then this operation will append the produced
/// signature to it.  The resulting VJSON will be written to stdout.  If no --wallet-uuid argument is
/// specified, then there must only be one wallet in the database, and that wallet will be used.  If there
/// is more than one wallet in the database, the --wallet-uuid argument must be specified.
#[derive(clap::Parser)]
pub struct WalletDIDSignVJSON {
    #[command(flatten)]
    pub wallet_args: WalletArgs,
    // TODO: The default behavior should be to fetch the latest DID document for the DID being used to
    // sign before signing, so that the latest version is used, and there should be an argument to disable
    // this behavior.
    #[command(flatten)]
    pub verification_method_args: VerificationMethodArgs,
    #[command(flatten)]
    pub vjson_store_args: VJSONStoreArgs,
    #[command(flatten)]
    pub vjson_storage_behavior_args: VJSONStorageBehaviorArgs,
    #[command(flatten)]
    pub verifier_resolver_args: VerifierResolverArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl WalletDIDSignVJSON {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let mut value: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
        // TODO: Use ref if possible
        let key_id_o = self
            .verification_method_args
            .key_id_o
            .map(|key_id| selfsign::KERIVerifier::try_from(key_id))
            .transpose()
            .map_err(|e| anyhow::anyhow!("Parse error in --key-id argument; error was: {}", e))?;
        let controlled_did_o = self.verification_method_args.controlled_did_o.as_deref();
        let wallet = self.wallet_args.get_wallet().await?;
        let vjson_store = self.vjson_store_args.get_vjson_store().await?;
        let verifier_resolver = self.verifier_resolver_args.get_verifier_resolver_map();

        // Do the processing
        did_webplus_cli_lib::wallet_did_sign_vjson(
            &mut value,
            &wallet,
            controlled_did_o,
            key_id_o,
            self.verification_method_args.key_purpose,
            &vjson_store,
            &verifier_resolver,
        )
        .await?;
        self.vjson_storage_behavior_args
            .store_if_requested(&value, &vjson_store, &verifier_resolver)
            .await?;

        // Print the signed-and-self-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(&value, &mut std::io::stdout())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
