use crate::{determine_http_scheme, get_did_doc_store, Result, SelfHashArgs};
use selfhash::{HashFunction, SelfHashable};
use std::{borrow::Cow, io::Write};

/// Read VJSON from stdin and verify it -- self-hash and all signatures.  If valid, the VJSON will be written to stdout.
///
/// Verifiable JSON has "self-hash slots" and "self-hash URL slots" which, in order to be valid, must
/// all specify the self-hash value of the JCS-serialized form of the JSON after setting each self-hash
/// slot and self-hash URL slot to the self-hash's placeholder value.
#[derive(clap::Parser)]
pub struct VerifyVJSON {
    /// Specify the URL to the SQLite DID doc store to use for the "full" resolver to use in this
    /// verify operation.  This is what stores validated DID docs.  It should have the form
    /// `sqlite://<local-path>`.
    // TODO: Figure out how not to print the env var value, since if it ever were a general postgres
    // url, it could contain a password.
    #[arg(
        name = "doc-store",
        env = "DID_WEBPLUS_DOC_STORE",
        short,
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/doc-store.db"
    )]
    pub did_doc_store_db_url: String,
    // TODO: Implement this
    // /// Optionally specify the URL of the "resolve" endpoint of the VDG to use for DID resolution
    // /// during this verify operation.  The URL can omit the scheme (i.e. the "https://" portion).
    // /// The URL must not contain a query string or fragment.
    // #[arg(
    //     name = "vdg",
    //     env = "DID_WEBPLUS_VDG",
    //     short,
    //     long,
    //     value_name = "URL",
    //     value_parser = parse_url_o(s),
    // )]
    // pub vdg_resolve_endpoint_o: Option<url::Url>,
    #[command(flatten)]
    pub self_hash_args: SelfHashArgs,
    /// Do not print a newline at the end of the output.
    #[arg(short, long)]
    pub no_newline: bool,
}

impl VerifyVJSON {
    pub async fn handle(self) -> Result<()> {
        // Read the JSON from stdin.
        let value: serde_json::Value = serde_json::from_reader(&mut std::io::stdin())
            .map_err(|e| anyhow::anyhow!("Input is expected to be valid JSON; error was {}", e))?;

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

        let self_hash_path_s = self.self_hash_args.parse_self_hash_paths();
        let self_hash_url_path_s = self.self_hash_args.parse_self_hash_url_paths();

        // Verify the self-hash with the "proofs" field still present.
        let mut json = {
            let json = selfhash::SelfHashableJSON::new(
                value.clone(),
                Cow::Borrowed(&self_hash_path_s),
                Cow::Borrowed(&self_hash_url_path_s),
            )
            .map_err(|e| anyhow::anyhow!("{}", e))?;
            log::debug!(
                "VJSON whose self-hashes will be verified: {}",
                json.value().to_string()
            );
            json.verify_self_hashes()
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            log::debug!("Input VJSON's self-hashes were successfully verified.");
            json
        };

        // The "proofs" field should be an array of JWS strings over the self-hash digest of the JSON
        // without its "proofs" field.
        let proof_vo = {
            let value_object = json.value_mut().as_object_mut().unwrap();
            if let Some(proofs_value) = value_object.remove("proofs") {
                let proof_value_v: Vec<serde_json::Value> = serde_json::from_value(proofs_value)?;
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

            let http_scheme = determine_http_scheme();
            let did_doc_store = get_did_doc_store(&self.did_doc_store_db_url).await?;

            // Validate the self-hash now that the "proofs" field is removed.  Then form the detached payload that is the
            // message that is supposed to be signed by each proof.
            json.set_self_hash_slots_to(selfhash::Blake3.placeholder_hash())
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let detached_payload_bytes = serde_json_canonicalizer::to_vec(json.value())?;

            // For each proof, verify that it's a valid detached JWS over the proof-removed JSON
            // that has its self-hash slots set to the placeholder hash value.
            for proof in proof_v.iter() {
                let jws = did_webplus_jws::JWS::try_from(proof.as_str())?;
                log::debug!("Verifying proof with JWS header: {:?}", jws.header());

                // Use "full" DID resolver to resolve the key specified in the JWS header.
                let mut transaction = did_doc_store.begin_transaction(None).await?;
                let _did_doc_record = did_webplus_resolver::resolve_did(
                    &did_doc_store,
                    &mut transaction,
                    jws.header().kid.without_fragment().as_str(),
                    http_scheme,
                )
                .await?;
                transaction.commit().await?;

                // Part of DID doc verification is ensuring that the key ID represents the same public key as
                // the JsonWebKey2020 value.  So we can use the key ID KERIVerifier value as the public key.
                // TODO: Assert that this is actually the case.
                let verifier = jws.header().kid.fragment();

                jws.verify(&verifier, Some(&mut detached_payload_bytes.as_slice()))?;
                log::debug!("Proof with JWS header {:?} was verified", jws.header());
            }
        }

        log::info!("Input VJSON was successfully verified");

        // JCS-serialize the verified JSON to stdout, and add a newline if specified.
        serde_json_canonicalizer::to_writer(&value, &mut std::io::stdout())?;
        if !self.no_newline {
            std::io::stdout().write("\n".as_bytes()).unwrap();
        }

        Ok(())
    }
}
