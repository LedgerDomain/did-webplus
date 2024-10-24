use crate::{NewlineArgs, PrivateKeyFileArgs, Result, SelfHashArgs};
use selfhash::{HashFunction, SelfHashable};
use std::{borrow::Cow, io::Read};

/// Produce VJSON (Verifiable JSON) by signing it using the private key from the specified file, then
/// self-hashing it.  The JSON will be read from stdin, and if there is an existing "proofs" field (where
/// the signatures are represented), then this operation will append the produced signature to it.  The
/// resulting VJSON will be written to stdout.
#[derive(clap::Parser)]
pub struct DIDKeySignVJSON {
    #[command(flatten)]
    pub private_key_file_args: PrivateKeyFileArgs,
    #[command(flatten)]
    pub self_hash_args: SelfHashArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDKeySignVJSON {
    pub fn handle(self) -> Result<()> {
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

        let self_hash_path_s = self.self_hash_args.parse_self_hash_paths();
        let self_hash_url_path_s = self.self_hash_args.parse_self_hash_url_paths();

        let mut json = selfhash::SelfHashableJSON::new(
            value,
            Cow::Borrowed(&self_hash_path_s),
            Cow::Borrowed(&self_hash_url_path_s),
        )
        .unwrap();

        self.private_key_file_args.ensure_file_exists()?;

        let signer_b = self.private_key_file_args.read_private_key_file()?;
        let did_resource =
            did_key::DIDResource::try_from(&signer_b.verifier().to_verifier_bytes())?;

        let jws = {
            json.set_self_hash_slots_to(selfhash::Blake3.placeholder_hash())
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            log::debug!("json that will be signed: {}", json.value().to_string());
            let payload_bytes = serde_json_canonicalizer::to_vec(json.value())?;
            did_webplus_jws::JWS::signed(
                did_resource.to_string(),
                &mut payload_bytes.as_slice(),
                did_webplus_jws::JWSPayloadPresence::Detached,
                did_webplus_jws::JWSPayloadEncoding::Base64URL,
                signer_b.as_ref(),
            )?
        };

        // Attach the JWS to the "proofs" array.
        proofs.push(serde_json::Value::String(jws.into_string()));

        // Re-add the "proofs" field to the json.
        let value_object = json.value_mut().as_object_mut().unwrap();
        value_object.insert("proofs".to_owned(), serde_json::Value::Array(proofs));

        // Self-hash the JSON with the "proofs" field populated.
        json.self_hash(selfhash::Blake3.new_hasher())
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        // Print the signed-and-self-hashed JSON and optional newline.
        serde_json_canonicalizer::to_writer(json.value(), &mut std::io::stdout())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
