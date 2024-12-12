use crate::{NewlineArgs, Result, VJSONStorageBehaviorArgs, VJSONStoreArgs, VerifierResolverArgs};

/// Read JSON from stdin and write self-hashed but non-signed Verifiable JSON (VJSON) to stdout.
///
/// Compute the Verifiable JSON (VJSON) from the given JSON input read from stdin.  Verifiable JSON
/// self-validating by using of a self-hashing procedure.  In particular, VJSON has at least one
/// "self-hash slot" which is used during the computation and verification of the JSON's self-hash.
/// During the computation of the JSON's self-hash, all the self-hash slots are set to a placeholder
/// value which encodes which hash function will be used, the JSON is serialized into JCS (JSON
/// Canonicalization Scheme), and then hashed.  This hash value is then used to set all the self-hash slots.
/// The JSON is then serialized into JCS again, and at this point is self-hashed and fully self-verifiable,
/// and is called VJSON.
#[derive(clap::Args)]
pub struct VJSONSelfHash {
    #[command(flatten)]
    pub vjson_store_args: VJSONStoreArgs,
    #[command(flatten)]
    pub vjson_storage_behavior_args: VJSONStorageBehaviorArgs,
    #[command(flatten)]
    pub verifier_resolver_args: VerifierResolverArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl VJSONSelfHash {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input
        let value = serde_json::from_reader(std::io::stdin())?;
        let vjson_store = self.vjson_store_args.get_vjson_store().await?;
        let verifier_resolver_map = self.verifier_resolver_args.get_verifier_resolver_map();

        // Do the processing
        let value = did_webplus_cli_lib::vjson_self_hash(value, &vjson_store).await?;
        self.vjson_storage_behavior_args
            .store_if_requested(&value, &vjson_store, &verifier_resolver_map)
            .await?;

        // Print the self-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(&value, &mut std::io::stdout()).unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
