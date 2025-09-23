use crate::{
    error_invalid_vjson, self_hashable_json_from, validate_against_json_schema, DirectDependencies,
    Error, Result, VJSONResolver, VJSONSchema,
};
use selfhash::{HashFunctionT, SelfHashableT};

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait Validate: selfhash::SelfHashableT<mbx::MBHashStr> {
    /// Validation must include self-hash validation or self-signature-and-hash validation, followed
    /// by any other type-specific validation checks.  This should return the self-hash of the validated
    /// object.
    async fn validate_and_return_self_hash(
        &self,
        vjson_resolver: &dyn VJSONResolver,
        verifier_resolver: &dyn verifier_resolver::VerifierResolver,
    ) -> Result<mbx::MBHash>;
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Validate for serde_json::Value {
    async fn validate_and_return_self_hash(
        &self,
        vjson_resolver: &dyn VJSONResolver,
        verifier_resolver: &dyn verifier_resolver::VerifierResolver,
    ) -> Result<mbx::MBHash> {
        tracing::debug!("validate_and_return_self_hash");

        // First, form the SelfHashableJSON object that will be used to verify the self-hashes.
        // This is what reads the $schema field, if present, and uses it to determine the self-hash
        // paths and self-hash URL paths.
        let (mut self_hashable_json, schema_value) =
            self_hashable_json_from(self.clone(), vjson_resolver).await?;

        validate_against_json_schema(&schema_value, self_hashable_json.value())?;

        let self_hash = {
            // The schema defines the JSONPath queries that define the self-hash [URL] slots, as well as
            // if this JSON blob is expected to be self-signed.
            let vjson_schema: VJSONSchema = serde_json::from_value(schema_value).map_err(|e| {
                Error::InvalidVJSON(
                    format!("VJSON schema was invalid JSON; error was: {}", e).into(),
                )
            })?;
            tracing::trace!(
                "    validate_and_return_self_hash; vjson_schema: {:?}",
                vjson_schema
            );

            // Verify the self-hash with the "proofs" field still present.

            tracing::trace!(
                "    validate_and_return_self_hash; VJSON whose self-hashes will be verified: {}",
                self_hashable_json.value().to_string()
            );
            let self_hash = self_hashable_json
                .verify_self_hashes()
                .map_err(error_invalid_vjson)?
                .to_owned();
            tracing::trace!("    validate_and_return_self_hash; Input VJSON's self-hashes were successfully verified.");

            // The "proofs" field should be an array of JWS strings over the self-hash digest of the JSON
            // without its "proofs" field.
            let proof_vo = {
                let value_object = self_hashable_json.value_mut().as_object_mut().unwrap();
                if let Some(proofs_value) = value_object.remove("proofs") {
                    let proof_value_v: Vec<serde_json::Value> =
                        serde_json::from_value(proofs_value)
                            .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    Some(
                        proof_value_v
                            .into_iter()
                            .map(|proof_value| serde_json::from_value::<String>(proof_value))
                            .collect::<serde_json::Result<Vec<String>>>()
                            .map_err(|e| Error::Malformed(e.to_string().into()))?,
                    )
                } else {
                    // No proofs, so verification only involves verifying self-hash, which was already done.
                    None
                }
            };

            // Verify proofs, if any are present.
            let mut valid_proof_count = 0usize;
            if let Some(proof_v) = proof_vo {
                tracing::trace!(
                    "    validate_and_return_self_hash; Now verifying VJSON proofs; there are {} proofs to verify",
                    proof_v.len()
                );

                // Validate the self-hash now that the "proofs" field is removed.  Then form the detached payload that is the
                // message that is supposed to be signed by each proof.
                let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
                self_hashable_json
                    .set_self_hash_slots_to(&mb_hash_function.placeholder_hash())
                    .map_err(|e| Error::InternalError(e.to_string().into()))?;
                let detached_payload_bytes =
                    serde_json_canonicalizer::to_vec(self_hashable_json.value()).unwrap();

                // For each proof, verify that it's a valid detached JWS over the proof-removed JSON
                // that has its self-hash slots set to the placeholder hash value.
                for (proof_index, proof) in proof_v.iter().enumerate() {
                    let jws = did_webplus_jws::JWS::try_from(proof.as_str())
                        .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    tracing::info!("    validate_and_return_self_hash; Verifying {}th proof with JWS header: {:?}", proof_index, jws.header());

                    // Determine the verifier (i.e. public key) to use to verify the JWS.
                    let verifier_b = verifier_resolver.resolve(&jws.header().kid).await.map_err(|e| Error::InvalidVJSON(format!("JWS header \"kid\" field was not a valid verifier; error was: {}", e).into()))?;

                    jws.verify(
                        verifier_b.as_ref(),
                        Some(&mut detached_payload_bytes.as_slice()),
                    )
                    .map_err(error_invalid_vjson)?;
                    valid_proof_count += 1;
                    tracing::trace!("    validate_and_return_self_hash; Proof with JWS header {:?} was verified", jws.header());
                }
            }

            if vjson_schema.vjson_properties.must_be_signed {
                if valid_proof_count == 0 {
                    return Err(Error::InvalidVJSON("VJSON required at least one element in the \"proofs\" array, but there were none".into()));
                }
            }

            // Validate the direct dependencies.
            //
            // For now, this really just means validate that they are VJSON values that have been validated
            // and stored by the VJSONStore.  If there were a way to fetch VJSON values from other stores,
            // then that could be done here.
            //
            // Eventually though, the "directDependencies" property of "vjsonProperties" could actually
            // specify what schema each direct dependency is expected to adhere to.

            tracing::trace!("    validate_and_return_self_hash; validating direct dependencies");
            for direct_dependency in self.direct_dependency_iter(vjson_resolver).await? {
                tracing::trace!(
                    "    validate_and_return_self_hash; direct dependency: {}",
                    direct_dependency
                );
                match vjson_resolver
                    .resolve_vjson_string(&direct_dependency)
                    .await
                {
                    Ok(_) => {
                        tracing::trace!(
                            "    validate_and_return_self_hash; direct dependency found"
                        );
                        // Good; nothing to do.
                    }
                    Err(Error::NotFound(_)) => {
                        return Err(Error::NotFound(
                            format!("Direct dependency {} could not be found", direct_dependency)
                                .into(),
                        ));
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }

            // TODO: Maybe? Handle other validations which may not be representable via JSON schema.
            // This would involve acting upon the custom keywords and other fields in the schema.

            self_hash
        };

        tracing::debug!("    validate_and_return_self_hash; successfully validated");

        Ok(self_hash)
    }
}
