use crate::{NewlineArgs, Result, VJSONStorageBehaviorArgs, VJSONStoreArgs, VerifierResolverArgs};
use selfhash::{HashFunction, SelfHashable};
use verifier_resolver::VerifierResolver;

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
        // Read the JSON from stdin.
        let value: serde_json::Value = serde_json::from_reader(&mut std::io::stdin())
            .map_err(|e| anyhow::anyhow!("Input is expected to be valid JSON; error was: {}", e))?;

        // Do basic validation of the input JSON.
        // TODO: This should be a schema validation, ideally as formal Verifiable JSON.
        {
            anyhow::ensure!(
                value.is_object(),
                "Input JSON is expected to be a JSON object"
            );
            let value_object = value.as_object().unwrap();
            if value_object.contains_key("proofs") {
                let proofs_value = value_object.get("proofs").unwrap();
                anyhow::ensure!(proofs_value.is_array(), "Input JSON is expected to be a JSON object having a \"proofs\" field that is an array");
                let proof_v = proofs_value.as_array().unwrap();
                for proof_value in proof_v.iter() {
                    anyhow::ensure!(proof_value.is_string(), "Each element of the \"proofs\" array in the input JSON is expected to be a string");
                }
            }
        }

        let vjson_store = self.vjson_store_args.get_vjson_store().await?;

        let (self_hashable_json, schema_value) = {
            let mut transaction = vjson_store.begin_transaction(None).await?;
            let (self_hashable_json, schema_value) =
                vjson_store::self_hashable_json_from(value.clone(), &mut transaction, &vjson_store)
                    .await?;
            vjson_store.commit_transaction(transaction).await?;
            (self_hashable_json, schema_value)
        };

        vjson_store::validate_against_json_schema(&schema_value, self_hashable_json.value())?;

        let verifier_resolver_map = self.verifier_resolver_args.get_verifier_resolver_map();

        {
            // Clone self_hashable_json because it has to be mutated in order to verify the proofs.
            let mut self_hashable_json = self_hashable_json.clone();
            // The "proofs" field should be an array of JWS strings over the self-hash digest of the JSON
            // without its "proofs" field.
            let proof_vo = {
                let value_object = self_hashable_json.value_mut().as_object_mut().unwrap();
                if let Some(proofs_value) = value_object.remove("proofs") {
                    let proof_value_v: Vec<serde_json::Value> =
                        serde_json::from_value(proofs_value)?;
                    Some(
                        proof_value_v
                            .into_iter()
                            .map(|proof_value| serde_json::from_value::<String>(proof_value))
                            .collect::<serde_json::Result<Vec<String>>>()?,
                    )
                } else {
                    // No proofs, so verification only involves verifying self-hash, which was already done.
                    None
                }
            };

            // Verify proofs, if any are present.
            if let Some(proof_v) = proof_vo {
                log::debug!(
                    "Now verifying VJSON proofs; there are {} proofs to verify",
                    proof_v.len()
                );

                // Now that the "proofs" field is removed, form the detached payload that is the message
                // that is supposed to be signed by each proof.
                self_hashable_json
                    .set_self_hash_slots_to(selfhash::Blake3.placeholder_hash())
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                let detached_payload_bytes =
                    serde_json_canonicalizer::to_vec(self_hashable_json.value())?;

                // For each proof, verify that it's a valid detached JWS over the proof-removed JSON
                // that has its self-hash slots set to the placeholder hash value.
                for proof in proof_v.iter() {
                    let jws = did_webplus_jws::JWS::try_from(proof.as_str())?;
                    log::debug!("Verifying proof with JWS header: {:?}", jws.header());

                    let verifier_b = verifier_resolver_map
                        .resolve(jws.header().kid.as_str())
                        .await?;

                    jws.verify(
                        verifier_b.as_ref(),
                        Some(&mut detached_payload_bytes.as_slice()),
                    )?;
                    log::debug!("Proof with JWS header {:?} was verified", jws.header());
                }
            }

            log::info!("Input VJSON was successfully verified");
        }

        self.vjson_storage_behavior_args
            .store_if_requested(
                &vjson_store,
                self_hashable_json.value(),
                &verifier_resolver_map,
            )
            .await?;

        // JCS-serialize the verified JSON to stdout, and add a newline if specified.
        serde_json_canonicalizer::to_writer(&value, &mut std::io::stdout())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
