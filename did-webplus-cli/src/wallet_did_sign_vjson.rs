use crate::{get_wallet, Result, SelfHashArgs};
use did_webplus_wallet_storage::LocallyControlledVerificationMethodFilter;
use selfhash::{HashFunction, SelfHashable};
use std::{
    borrow::Cow,
    io::{Read, Write},
};

/// Produce VJSON (Verifiable JSON) by signing it using the specified DID and specified key purpose from the
/// specified wallet, then self-hashing it.  The JSON will be read from stdin, and if there is an existing
/// "proofs" field (where the signatures are represented), then this operation will append the produced
/// signature to it.  The resulting VJSON will be written to stdout.
#[derive(clap::Parser)]
pub struct WalletDIDSignVJSON {
    /// Specify the URL to the wallet database.  The URL must start with "sqlite://".
    #[arg(
        short = 'u',
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/wallet.db"
    )]
    pub wallet_db_url: String,
    /// Specify the UUID of the wallet within the database to use.  If not specified, then either the
    /// only wallet in the database will be used, or a new wallet will be created.  If there is more
    /// than one wallet in the database, an error will be returned.
    #[arg(name = "wallet-uuid", short = 'w', long, value_name = "UUID")]
    pub wallet_uuid_o: Option<String>,
    /// Specify the DID to be used for signing.  If not specified and there is exactly one DID controlled by
    /// the wallet, then that DID will be used -- it is uniquely determinable.  If there is no uniquely
    /// determinable DID, then an error will be returned.
    #[arg(name = "did", short, long, value_name = "DID")]
    pub did_o: Option<did_webplus::DID>,
    /// Specify which key purpose to use when signing the JWS.  Valid values are "authentication",
    /// "assertionMethod", "keyAgreement", "capabilityInvocation", and "capabilityDelegation".
    #[arg(short = 'p', long, value_name = "PURPOSE")]
    pub key_purpose: did_webplus::KeyPurpose,
    /// If specified, then use key with the given public key when signing the JWS.  If not specified,
    /// then use the uniquely determinable key if there is one.  Otherwise return error.
    #[arg(name = "key-id", short = 'k', long, value_name = "KEY_ID")]
    pub key_id_o: Option<String>,
    #[command(flatten)]
    pub self_hash_args: SelfHashArgs,
    /// Do not print a newline at the end of the output.
    #[arg(short, long)]
    pub no_newline: bool,
}

impl WalletDIDSignVJSON {
    pub async fn handle(self) -> Result<()> {
        let wallet_uuid_o = self
            .wallet_uuid_o
            .map(|wallet_uuid_string| uuid::Uuid::parse_str(&wallet_uuid_string))
            .transpose()?;
        let key_id_o = self
            .key_id_o
            .map(|key_id| selfsign::KERIVerifier::try_from(key_id))
            .transpose()
            .map_err(|e| anyhow::anyhow!("Parse error in --key-id argument; error was {}", e))?;

        let wallet = get_wallet(&self.wallet_db_url, wallet_uuid_o.as_ref()).await?;

        use did_webplus_wallet::Wallet;
        let controlled_did = wallet.get_controlled_did(self.did_o.as_deref()).await?;

        // Get the specified signing key.
        let (verification_method_record, priv_key_record) = {
            let query_result_v = wallet
                .get_locally_controlled_verification_methods(
                    &LocallyControlledVerificationMethodFilter {
                        did_o: Some(controlled_did.did().to_owned()),
                        key_purpose_o: Some(self.key_purpose),
                        version_id_o: None,
                        key_id_o,
                        result_limit_o: Some(2),
                    },
                )
                .await?;
            if query_result_v.is_empty() {
                anyhow::bail!(
                    "No locally controlled verification method found for KeyPurpose \"{}\" and {}",
                    self.key_purpose,
                    controlled_did
                );
            }
            if query_result_v.len() > 1 {
                anyhow::bail!("Multiple locally controlled verification methods found for KeyPurpose \"{}\" and {}; use --key-id to select a single key", self.key_purpose, controlled_did);
            }
            query_result_v.into_iter().next().unwrap()
        };

        let signer = priv_key_record.private_key_bytes_o.unwrap();

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

        let jws = {
            json.set_self_hash_slots_to(selfhash::Blake3.placeholder_hash())
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            log::debug!("json that will be signed: {}", json.value().to_string());
            let payload_bytes = serde_json_canonicalizer::to_vec(json.value())?;
            did_webplus_jws::JWS::signed(
                verification_method_record.did_key_resource_fully_qualified,
                &mut payload_bytes.as_slice(),
                did_webplus_jws::JWSPayloadPresence::Detached,
                did_webplus_jws::JWSPayloadEncoding::Base64URL,
                &signer,
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
        if !self.no_newline {
            std::io::stdout().write_all(b"\n")?;
        }

        Ok(())
    }
}
