use crate::{
    error_invalid_vjson, error_malformed, self_hashable_json_from, validate_against_json_schema,
    DirectDependencies, Error, Result, VJSONSchema, VJSONStorage, VJSONStore,
};
use selfhash::{HashFunction, SelfHashable};

#[async_trait::async_trait]
pub trait Validate: selfhash::SelfHashable {
    /// Validation must include self-hash validation or self-signature-and-hash validation, followed
    /// by any other type-specific validation checks.  This should return the self-hash of the validated
    /// object.
    // TEMP HACK -- this should take a &dyn Trait for some Resolver trait or something.
    async fn validate_and_return_self_hash<Storage: VJSONStorage>(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        vjson_store: &VJSONStore<Storage>,
    ) -> Result<selfhash::KERIHash>;
}

#[async_trait::async_trait]
impl Validate for serde_json::Value {
    async fn validate_and_return_self_hash<Storage: VJSONStorage>(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        vjson_store: &VJSONStore<Storage>,
    ) -> Result<selfhash::KERIHash> {
        log::debug!("validate_and_return_self_hash");

        // First, form the SelfHashableJSON object that will be used to verify the self-hashes.
        // This is what reads the $schema field, if present, and uses it to determine the self-hash
        // paths and self-hash URL paths.
        let (mut self_hashable_json, schema_value) =
            self_hashable_json_from(self.clone(), &mut *transaction, vjson_store).await?;

        validate_against_json_schema(&schema_value, self_hashable_json.value())?;

        let self_hash = {
            // The schema defines the JSONPath queries that define the self-hash [URL] slots, as well as
            // if this JSON blob is expected to be self-signed.
            let vjson_schema: VJSONSchema = serde_json::from_value(schema_value).map_err(|e| {
                Error::InvalidVJSON(
                    format!("VJSON schema was invalid JSON; error was: {}", e).into(),
                )
            })?;
            log::trace!(
                "    validate_and_return_self_hash; vjson_schema: {:?}",
                vjson_schema
            );

            // Verify the self-hash with the "proofs" field still present.

            log::trace!(
                "    validate_and_return_self_hash; VJSON whose self-hashes will be verified: {}",
                self_hashable_json.value().to_string()
            );
            let self_hash = self_hashable_json
                .verify_self_hashes()
                .map_err(error_invalid_vjson)?
                .to_keri_hash()
                .map_err(error_malformed)?
                .into_owned();
            log::trace!("    validate_and_return_self_hash; Input VJSON's self-hashes were successfully verified.");

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
                log::trace!(
                    "    validate_and_return_self_hash; Now verifying VJSON proofs; there are {} proofs to verify",
                    proof_v.len()
                );

                // Validate the self-hash now that the "proofs" field is removed.  Then form the detached payload that is the
                // message that is supposed to be signed by each proof.
                self_hashable_json
                    .set_self_hash_slots_to(selfhash::Blake3.placeholder_hash())
                    .map_err(|e| Error::InternalError(e.to_string().into()))?;
                let detached_payload_bytes =
                    serde_json_canonicalizer::to_vec(self_hashable_json.value()).unwrap();

                // For each proof, verify that it's a valid detached JWS over the proof-removed JSON
                // that has its self-hash slots set to the placeholder hash value.
                for (proof_index, proof) in proof_v.iter().enumerate() {
                    let jws = did_webplus_jws::JWS::try_from(proof.as_str())
                        .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    log::info!("    validate_and_return_self_hash; Verifying {}th proof with JWS header: {:?}", proof_index, jws.header());

                    // TODO: Abstract this into a JWS verifier trait, so that details of specific DID methods
                    // don't appear here.

                    // Depending on the DID method specified by the JWS header kid field, use different resolution methods.
                    let verifier_b: Box<dyn selfsign::Verifier> = if jws
                        .header()
                        .kid
                        .starts_with("did:key:")
                    {
                        log::trace!(
                            "    validate_and_return_self_hash; JWS header \"kid\" was {:?}; verifying using did:key method",
                            jws.header().kid
                        );
                        let did_resource = did_key::DIDResourceStr::new_ref(&jws.header().kid)
                            .map_err(error_malformed)?;
                        did_resource.did().to_verifier()
                    } else if jws.header().kid.starts_with("did:webplus:") {
                        todo!("did:webplus JWS verification not yet implemented");
                        // log::trace!(
                        //     "    validate_and_return_self_hash; JWS header \"kid\" was {:?}; verifying using did:webplus method",
                        //     jws.header().kid
                        // );
                        // let did_key_resource_fully_qualified =
                        //     DIDKeyResourceFullyQualifiedStr::new_ref(&jws.header().kid)?;

                        // // Use "full" DID resolver to resolve the key specified in the JWS header.
                        // let mut transaction = did_doc_store.begin_transaction(None).await?;
                        // let _did_doc_record = did_webplus_resolver::resolve_did(
                        //     &did_doc_store,
                        //     &mut transaction,
                        //     did_key_resource_fully_qualified.without_fragment().as_str(),
                        //     http_scheme,
                        // )
                        // .await?;
                        // transaction.commit().await?;

                        // // Part of DID doc verification is ensuring that the key ID represents the same public key as
                        // // the JsonWebKey2020 value.  So we can use the key ID KERIVerifier value as the public key.
                        // // TODO: Assert that this is actually the case.
                        // Box::new(did_key_resource_fully_qualified.fragment())
                    } else {
                        return Err(Error::Unsupported(format!(
                                "JWS header \"kid\" field was {}, which uses an unsupported DID method",
                                jws.header().kid
                            ).into()));
                    };

                    jws.verify(
                        verifier_b.as_ref(),
                        Some(&mut detached_payload_bytes.as_slice()),
                    )
                    .map_err(error_invalid_vjson)?;
                    valid_proof_count += 1;
                    log::trace!("    validate_and_return_self_hash; Proof with JWS header {:?} was verified", jws.header());
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

            log::trace!("    validate_and_return_self_hash; validating direct dependencies");
            let mut transaction = vjson_store.begin_transaction(None).await?;
            for direct_dependency in self.direct_dependency_iter(vjson_store).await? {
                log::trace!(
                    "    validate_and_return_self_hash; direct dependency: {}",
                    direct_dependency
                );
                match vjson_store
                    .get_vjson_str(&mut transaction, &direct_dependency)
                    .await
                {
                    Ok(_) => {
                        log::trace!("    validate_and_return_self_hash; direct dependency found");
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
            vjson_store.commit_transaction(transaction).await?;

            // TODO: Maybe? Handle other validations which may not be representable via JSON schema.
            // This would involve acting upon the custom keywords and other fields in the schema.

            self_hash
        };

        log::debug!("    validate_and_return_self_hash; successfully validated");

        Ok(self_hash)
    }
}
