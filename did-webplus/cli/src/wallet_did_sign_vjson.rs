use crate::{
    NewlineArgs, Result, VJSONStorageBehaviorArgs, VJSONStoreArgs, VerificationMethodArgs,
    VerifierResolverArgs, WalletArgs,
};
use did_webplus_wallet_store::LocallyControlledVerificationMethodFilter;
use selfhash::{HashFunction, SelfHashable};
use std::io::Read;

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
        let key_id_o = self
            .verification_method_args
            .key_id_o
            .map(|key_id| selfsign::KERIVerifier::try_from(key_id))
            .transpose()
            .map_err(|e| anyhow::anyhow!("Parse error in --key-id argument; error was: {}", e))?;

        let wallet = self.wallet_args.get_wallet().await?;

        use did_webplus_wallet::Wallet;
        let controlled_did = wallet
            .get_controlled_did(self.verification_method_args.did_o.as_deref())
            .await?;

        let verifier_resolver_map = self.verifier_resolver_args.get_verifier_resolver_map();

        // Get the specified signing key.
        let (verification_method_record, signer_b) = {
            let query_result_v = wallet
                .get_locally_controlled_verification_methods(
                    &LocallyControlledVerificationMethodFilter {
                        did_o: Some(controlled_did.did().to_owned()),
                        key_purpose_o: Some(self.verification_method_args.key_purpose),
                        version_id_o: None,
                        key_id_o,
                        result_limit_o: Some(2),
                    },
                )
                .await?;
            if query_result_v.is_empty() {
                anyhow::bail!(
                    "No locally controlled verification method found for KeyPurpose \"{}\" and {}",
                    self.verification_method_args.key_purpose,
                    controlled_did
                );
            }
            if query_result_v.len() > 1 {
                anyhow::bail!("Multiple locally controlled verification methods found for KeyPurpose \"{}\" and {}; use --key-id to select a single key", self.verification_method_args.key_purpose, controlled_did);
            }
            query_result_v.into_iter().next().unwrap()
        };

        // Read all of stdin into a String and parse it as JSON.
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&input)?;

        let mut proofs = {
            anyhow::ensure!(value.is_object(), "JSON must be an object");
            let value_object = value.as_object_mut().unwrap();
            // Extract the "proofs" field, if it exists, and if so, ensure that it's an array.  We will
            // add the proof to it, and re-add it after signing.
            match value_object.remove("proofs") {
                None => {
                    // No existing "proofs" field, this is fine.  Create an empty array to be populated later.
                    Vec::new()
                }
                Some(serde_json::Value::Array(proofs)) => {
                    // Existing "proofs" field that is an array, as expected.  Use it.
                    proofs
                }
                Some(_) => {
                    anyhow::bail!("\"proofs\" field, if it exists, must be an array");
                }
            }
        };

        let vjson_store = self.vjson_store_args.get_vjson_store().await?;

        let mut self_hashable_json = {
            let mut transaction = vjson_store.begin_transaction(None).await?;
            let (self_hashable_json, _schema_value) =
                vjson_store::self_hashable_json_from(value, &mut transaction, &vjson_store).await?;
            vjson_store.commit_transaction(transaction).await?;
            self_hashable_json
        };

        let jws = {
            self_hashable_json
                .set_self_hash_slots_to(selfhash::Blake3.placeholder_hash())
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            log::debug!(
                "json that will be signed: {}",
                self_hashable_json.value().to_string()
            );
            let payload_bytes = serde_json_canonicalizer::to_vec(self_hashable_json.value())?;
            did_webplus_jws::JWS::signed(
                verification_method_record
                    .did_key_resource_fully_qualified
                    .to_string(),
                &mut payload_bytes.as_slice(),
                did_webplus_jws::JWSPayloadPresence::Detached,
                did_webplus_jws::JWSPayloadEncoding::Base64URL,
                signer_b.as_ref(),
            )?
        };

        // Attach the JWS to the "proofs" array.
        proofs.push(serde_json::Value::String(jws.into_string()));

        // Re-add the "proofs" field to the json.
        let value_object = self_hashable_json.value_mut().as_object_mut().unwrap();
        value_object.insert("proofs".to_owned(), serde_json::Value::Array(proofs));

        // Self-hash the JSON with the "proofs" field populated.
        self_hashable_json
            .self_hash(selfhash::Blake3.new_hasher())
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        self.vjson_storage_behavior_args
            .store_if_requested(
                &vjson_store,
                self_hashable_json.value(),
                &verifier_resolver_map,
            )
            .await?;

        // Print the signed-and-self-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(self_hashable_json.value(), &mut std::io::stdout())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        // TODO: Should we validate the VJSON here?

        Ok(())
    }
}
