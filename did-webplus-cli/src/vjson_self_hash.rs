use crate::{NewlineArgs, Result, VJSONStorageBehaviorArgs, VJSONStoreArgs};
use selfhash::{HashFunction, SelfHashable};
use std::io::Read;

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
    pub newline_args: NewlineArgs,
}

impl VJSONSelfHash {
    pub async fn handle(self) -> Result<()> {
        // Read all of stdin into a String and parse it as JSON.
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let value = serde_json::from_str(&input).unwrap();

        let vjson_store = self.vjson_store_args.get_vjson_store().await?;

        let (mut self_hashable_json, _schema_value) = {
            let mut transaction = vjson_store.begin_transaction(None).await?;
            let (self_hashable_json, schema_value) =
                vjson_store::self_hashable_json_from(value, &mut transaction, &vjson_store).await?;
            vjson_store.commit_transaction(transaction).await?;
            (self_hashable_json, schema_value)
        };

        // Self-hash the JSON.
        // TODO: Arg to specify the hash function
        self_hashable_json
            .self_hash(selfhash::Blake3.new_hasher())
            .expect("self-hash failed");

        // Verify the self-hash.  This is mostly a sanity check.
        self_hashable_json
            .verify_self_hashes()
            .expect("programmer error: self-hash verification failed");

        self.vjson_storage_behavior_args
            .store_if_requested(&vjson_store, self_hashable_json.value())
            .await?;

        // Print the self-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(self_hashable_json.value(), &mut std::io::stdout())
            .unwrap();
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
