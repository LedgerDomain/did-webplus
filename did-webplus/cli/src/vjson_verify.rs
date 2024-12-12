use crate::{NewlineArgs, Result, VJSONStorageBehaviorArgs, VJSONStoreArgs, VerifierResolverArgs};

/// Read VJSON from stdin and verify it, using the "full" resolver with the specified DID doc store.
/// Verification includes verifying self-hash and all signatures.  If valid, the VJSON will be written
/// to stdout.  If requested, the verified will be stored in the VJSON store (default behavior is to store).
///
/// Verifiable JSON has "self-hash slots" and "self-hash URL slots" which, in order to be valid, must
/// all specify the self-hash value of the JCS-serialized form of the JSON after setting each self-hash
/// slot and self-hash URL slot to the self-hash's placeholder value.
#[derive(clap::Parser)]
pub struct VJSONVerify {
    #[command(flatten)]
    pub vjson_store_args: VJSONStoreArgs,
    #[command(flatten)]
    pub vjson_storage_behavior_args: VJSONStorageBehaviorArgs,
    #[command(flatten)]
    pub verifier_resolver_args: VerifierResolverArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl VJSONVerify {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let value = serde_json::from_reader(std::io::stdin())?;
        let vjson_store = self.vjson_store_args.get_vjson_store().await?;
        let verifier_resolver = self.verifier_resolver_args.get_verifier_resolver_map();

        // Do the processing
        did_webplus_cli_lib::vjson_verify(&value, &vjson_store, &verifier_resolver).await?;
        tracing::info!("Input VJSON was successfully verified");
        self.vjson_storage_behavior_args
            .store_if_requested(&value, &vjson_store, &verifier_resolver)
            .await?;

        // JCS-serialize the verified JSON to stdout, and add a newline if specified.
        serde_json_canonicalizer::to_writer(&value, &mut std::io::stdout())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
