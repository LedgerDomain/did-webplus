use crate::{
    NewlineArgs, PrivateKeyFileArgs, Result, VJSONStorageBehaviorArgs, VJSONStoreArgs,
    VerifierResolverArgs,
};

/// Produce VJSON (Verifiable JSON) by signing it using the private key from the specified file, then
/// self-hashing it.  The JSON will be read from stdin, and if there is an existing "proofs" field (where
/// the signatures are represented), then this operation will append the produced signature to it.  The
/// resulting VJSON will be written to stdout.
#[derive(clap::Parser)]
pub struct DIDKeySignVJSON {
    #[command(flatten)]
    pub private_key_file_args: PrivateKeyFileArgs,
    #[command(flatten)]
    pub vjson_store_args: VJSONStoreArgs,
    #[command(flatten)]
    pub vjson_storage_behavior_args: VJSONStorageBehaviorArgs,
    #[command(flatten)]
    pub verifier_resolver_args: VerifierResolverArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDKeySignVJSON {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let mut value: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
        let vjson_store = self.vjson_store_args.get_vjson_store().await?;
        self.private_key_file_args.ensure_file_exists()?;
        let signer_b = self.private_key_file_args.read_private_key_file()?;
        let verifier_resolver_map = self.verifier_resolver_args.get_verifier_resolver_map();

        // Do the processing
        did_webplus_cli_lib::did_key_sign_vjson(&mut value, signer_b.as_ref(), &vjson_store)
            .await?;
        self.vjson_storage_behavior_args
            .store_if_requested(&value, &vjson_store, &verifier_resolver_map)
            .await?;

        // Print the signed-and-self-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(&value, &mut std::io::stdout())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
