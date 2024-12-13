pub use anyhow::Result;

pub fn did_key_from_private(signer: &dyn selfsign::Signer) -> Result<did_key::DID> {
    Ok(did_key::DID::try_from(
        &signer.verifier().to_verifier_bytes(),
    )?)
}

// pub fn did_key_generate(key_type: selfsign::KeyType) -> Box<dyn selfsign::Signer> {
//     match key_type {
//         selfsign::KeyType::Ed25519 => {
//             #[cfg(feature = "ed25519-dalek")]
//             {
//                 Box::new(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng))
//             }
//             #[cfg(not(feature = "ed25519-dalek"))]
//             {
//                 panic!("Must enable the `ed25519-dalek` feature to generate Ed25519 keys");
//             }
//         }
//         selfsign::KeyType::Secp256k1 => {
//             #[cfg(feature = "k256")]
//             {
//                 Box::new(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng))
//             }
//             #[cfg(not(feature = "k256"))]
//             {
//                 panic!("Must enable the `k256` feature to generate Secp256k1 keys");
//             }
//         }
//     }
// }

/// PEM is a common format for representing cryptographic keys, e.g. for storing in a file.
// TODO: Make a browser-specific version of this that writes to some appropriate kind of browser storage.
pub fn did_key_generate_to_pkcs8_pem_file(
    key_type: selfsign::KeyType,
    private_key_path: &std::path::Path,
) -> Result<did_key::DID> {
    match key_type {
        selfsign::KeyType::Ed25519 => {
            #[cfg(feature = "ed25519-dalek")]
            {
                let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
                use selfsign::Signer;
                let did = did_key::DID::try_from(&signing_key.verifier().to_verifier_bytes())?;
                use ed25519_dalek::pkcs8::EncodePrivateKey;
                signing_key
                    .write_pkcs8_pem_file(private_key_path, Default::default())
                    .map_err(|e| {
                        anyhow::anyhow!("failed to write generated key; error was: {}", e)
                    })?;
                Ok(did)
            }

            #[cfg(not(feature = "ed25519-dalek"))]
            {
                let _ = private_key_path;
                panic!("Must enable the `ed25519-dalek` feature to generate Ed25519 keys");
            }
        }
        selfsign::KeyType::Secp256k1 => {
            #[cfg(feature = "k256")]
            {
                let signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
                use selfsign::Signer;
                let did = did_key::DID::try_from(&signing_key.verifier().to_verifier_bytes())?;
                let secret_key = k256::elliptic_curve::SecretKey::from(signing_key);
                use k256::pkcs8::EncodePrivateKey;
                secret_key
                    .write_pkcs8_pem_file(private_key_path, Default::default())
                    .map_err(|e| {
                        anyhow::anyhow!("failed to write generated key; error was: {}", e)
                    })?;
                Ok(did)
            }

            #[cfg(not(feature = "k256"))]
            {
                let _ = private_key_path;
                panic!("Must enable the `k256` feature to generate Secp256k1 keys");
            }
        }
    }
}

// /// PEM is a common format for representing cryptographic keys, e.g. for storing in a file.
// pub fn did_key_generate_to_pkcs8_pem(
//     key_type: selfsign::KeyType,
// ) -> Result<(did_key::DID, Zeroizing<String>)> {
//     match key_type {
//         selfsign::KeyType::Ed25519 => {
//             #[cfg(feature = "ed25519-dalek")]
//             {
//                 let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
//                 use selfsign::Signer;
//                 let did = did_key::DID::try_from(&signing_key.verifier().to_verifier_bytes())?;
//                 use ed25519_dalek::pkcs8::EncodePrivateKey;
//                 Ok((
//                     did,
//                     signing_key
//                         .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)?,
//                 ))
//             }
//             #[cfg(not(feature = "ed25519-dalek"))]
//             {
//                 panic!("Must enable the `ed25519-dalek` feature to generate Ed25519 keys");
//             }
//         }
//         selfsign::KeyType::Secp256k1 => {
//             #[cfg(feature = "k256")]
//             {
//                 let signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
//                 use selfsign::Signer;
//                 let did = did_key::DID::try_from(&signing_key.verifier().to_verifier_bytes())?;
//                 let secret_key = k256::elliptic_curve::SecretKey::from(signing_key);
//                 use k256::pkcs8::EncodePrivateKey;
//                 Ok((did, secret_key.to_pkcs8_pem(k256::pkcs8::LineEnding::LF)?))
//             }
//             #[cfg(not(feature = "k256"))]
//             {
//                 panic!("Must enable the `k256` feature to generate Secp256k1 keys");
//             }
//         }
//     }
// }

pub fn did_key_sign_jws(
    payload_bytes: &mut dyn std::io::Read,
    payload_presence: did_webplus_jws::JWSPayloadPresence,
    payload_encoding: did_webplus_jws::JWSPayloadEncoding,
    signer: &dyn selfsign::Signer,
) -> Result<did_webplus_jws::JWS<'static>> {
    let did_resource = did_key::DIDResource::try_from(&signer.verifier().to_verifier_bytes())?;
    let jws = did_webplus_jws::JWS::signed(
        did_resource.to_string(),
        payload_bytes,
        payload_presence,
        payload_encoding,
        signer,
    )?;
    Ok(jws)
}

pub async fn did_key_sign_vjson(
    value: &mut serde_json::Value,
    signer: &dyn selfsign::Signer,
    vjson_resolver: &dyn vjson_core::VJSONResolver,
) -> Result<()> {
    let did_resource = did_key::DIDResource::try_from(&signer.verifier().to_verifier_bytes())?;
    let kid = did_resource.to_string();
    let verifier_resolver = verifier_resolver::VerifierResolverDIDKey;
    vjson_core::sign_and_self_hash_vjson(
        value,
        kid,
        signer,
        vjson_resolver,
        Some(&verifier_resolver),
    )
    .await?;
    Ok(())
}

// TODO: Rename this function to something more appropriate
pub async fn did_list<Storage: did_webplus_doc_store::DIDDocStorage>(
    did_doc_storage: &Storage,
    did_doc_record_filter: &did_webplus_doc_store::DIDDocRecordFilter,
) -> Result<Vec<did_webplus_doc_store::DIDDocRecord>> {
    let mut transaction = did_doc_storage.begin_transaction(None).await?;
    let did_doc_record_v = did_doc_storage
        .get_did_doc_records(&mut transaction, &did_doc_record_filter)
        .await?;
    did_doc_storage.commit_transaction(transaction).await?;
    Ok(did_doc_record_v)
}

/// Resolve a DIDDocument.
pub async fn did_resolve(
    did_query: &str,
    did_resolver: &dyn did_webplus_resolver::DIDResolver,
) -> Result<did_webplus_core::DIDDocument> {
    // TODO: Handle metadata
    let (did_document, _did_doc_metadata) = did_resolver
        .resolve_did_document(
            did_query,
            did_webplus_core::RequestedDIDDocumentMetadata::none(),
        )
        .await?;
    Ok(did_document)
}

/// A weaker version of did_resolve, returning only the String form of the DID Document, instead of
/// the serde_json-deserialized form.
pub async fn did_resolve_string(
    did_query: &str,
    did_resolver: &dyn did_webplus_resolver::DIDResolver,
) -> Result<String> {
    // TODO: Handle metadata
    let (did_document_string, _did_doc_metadata) = did_resolver
        .resolve_did_document_string(
            did_query,
            did_webplus_core::RequestedDIDDocumentMetadata::none(),
        )
        .await?;
    Ok(did_document_string)
}

pub async fn jws_verify(
    jws: &did_webplus_jws::JWS<'_>,
    detached_payload_bytes_o: Option<&mut dyn std::io::Read>,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
) -> Result<()> {
    anyhow::ensure!(jws.header().kid.starts_with("did:"), "JWS header \"kid\" field (which was {:?}) is expected to be a DID, i.e. start with \"did:\"", jws.header().kid);

    // Determine the verifier (i.e. public key) to use to verify the JWS.
    let verifier_b = verifier_resolver.resolve(jws.header().kid.as_str()).await?;
    // Verify the JWS.
    jws.verify(verifier_b.as_ref(), detached_payload_bytes_o)?;

    Ok(())
}

// TODO: Move part of this into vjson_core.
pub async fn vjson_self_hash(
    value: serde_json::Value,
    vjson_resolver: &dyn vjson_core::VJSONResolver,
) -> Result<serde_json::Value> {
    let (mut self_hashable_json, _schema_value) =
        vjson_core::self_hashable_json_from(value, vjson_resolver).await?;

    // Self-hash the JSON.
    use selfhash::{HashFunction, SelfHashable};
    self_hashable_json
        .self_hash(selfhash::Blake3.new_hasher())
        .expect("self-hash failed");

    // Verify the self-hash.  This is mostly a sanity check.
    self_hashable_json
        .verify_self_hashes()
        .expect("programmer error: self-hash verification failed");

    Ok(self_hashable_json.into_value())
}

pub async fn vjson_store_add_str<Storage: vjson_store::VJSONStorage>(
    vjson_str: &str,
    vjson_store: &vjson_store::VJSONStore<Storage>,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
    already_exists_policy: vjson_store::AlreadyExistsPolicy,
) -> Result<()> {
    let mut transaction = vjson_store.begin_transaction(None).await?;
    vjson_store
        .add_vjson_str(
            &mut transaction,
            vjson_str,
            verifier_resolver,
            already_exists_policy,
        )
        .await?;
    vjson_store.commit_transaction(transaction).await?;
    Ok(())
}

pub async fn vjson_store_add_value<Storage: vjson_store::VJSONStorage>(
    vjson_value: &serde_json::Value,
    vjson_store: &vjson_store::VJSONStore<Storage>,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
    already_exists_policy: vjson_store::AlreadyExistsPolicy,
) -> Result<()> {
    let mut transaction = vjson_store.begin_transaction(None).await?;
    vjson_store
        .add_vjson_value(
            &mut transaction,
            vjson_value,
            verifier_resolver,
            already_exists_policy,
        )
        .await?;
    vjson_store.commit_transaction(transaction).await?;
    Ok(())
}

pub async fn vjson_store_get_value<Storage: vjson_store::VJSONStorage>(
    self_hash: &selfhash::KERIHashStr,
    vjson_store: &vjson_store::VJSONStore<Storage>,
) -> Result<serde_json::Value> {
    // Retrieve the specified VJSON value from the VJSON store.  This guarantees it's valid.
    let mut transaction = vjson_store.begin_transaction(None).await?;
    let vjson_value = vjson_store
        .get_vjson_value(&mut transaction, &self_hash)
        .await?;
    vjson_store.commit_transaction(transaction).await?;
    Ok(vjson_value)
}

pub async fn vjson_store_get_record<Storage: vjson_store::VJSONStorage>(
    self_hash: &selfhash::KERIHashStr,
    vjson_store: &vjson_store::VJSONStore<Storage>,
) -> Result<vjson_store::VJSONRecord> {
    // Retrieve the specified VJSONRecord from the VJSON store.  This guarantees the VJSON is valid.
    let mut transaction = vjson_store.begin_transaction(None).await?;
    let vjson_record = vjson_store
        .get_vjson_record(&mut transaction, &self_hash)
        .await?;
    vjson_store.commit_transaction(transaction).await?;
    Ok(vjson_record)
}

pub async fn vjson_verify(
    value: &serde_json::Value,
    vjson_resolver: &dyn vjson_core::VJSONResolver,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
) -> Result<selfhash::KERIHash> {
    use vjson_core::Validate;
    let self_hash = value
        .validate_and_return_self_hash(vjson_resolver, verifier_resolver)
        .await?;
    Ok(self_hash)
}

pub async fn wallet_did_create(
    wallet: &dyn did_webplus_wallet::Wallet,
    vdr_did_create_endpoint: &str,
) -> Result<did_webplus_core::DIDFullyQualified> {
    Ok(wallet.create_did(vdr_did_create_endpoint).await?)
}

pub async fn wallet_did_update(
    wallet: &dyn did_webplus_wallet::Wallet,
    did: &did_webplus_core::DIDStr,
    vdr_scheme: &'static str,
) -> Result<did_webplus_core::DIDFullyQualified> {
    Ok(wallet.update_did(&did, vdr_scheme).await?)
}

/// List DIDs controlled by the given wallet.  Optionally filter on the given DID.
pub async fn wallet_did_list(
    wallet: &dyn did_webplus_wallet::Wallet,
    did_o: Option<&did_webplus_core::DIDStr>,
) -> Result<Vec<did_webplus_core::DIDFullyQualified>> {
    Ok(wallet.get_controlled_dids(did_o).await?)
}

/// Select a unique key from the wallet using the given filters.
// TODO: Document precisely how the signing method filter vars work.
async fn wallet_did_select_key(
    wallet: &dyn did_webplus_wallet::Wallet,
    controlled_did_o: Option<&did_webplus_core::DIDStr>,
    key_purpose_o: Option<did_webplus_core::KeyPurpose>,
    key_id_o: Option<&selfsign::KERIVerifierStr>,
) -> Result<(
    did_webplus_wallet_store::VerificationMethodRecord,
    Box<dyn selfsign::Signer>,
)> {
    let query_result_v = wallet
        .get_locally_controlled_verification_methods(
            &did_webplus_wallet_store::LocallyControlledVerificationMethodFilter {
                // did_o: Some(controlled_did.did().to_owned()),
                did_o: controlled_did_o.map(|did| did.to_owned()),
                key_purpose_o,
                version_id_o: None,
                key_id_o: key_id_o.map(|key_id| key_id.to_owned()),
                result_limit_o: Some(2),
            },
        )
        .await?;
    if query_result_v.len() != 1 {
        let multiplicity = if query_result_v.len() > 1 {
            "Multiple"
        } else {
            "No"
        };
        anyhow::bail!(
            "{} locally controlled verification method(s) found for filter arguments{}{}{} -- Must specify appropriate filter arguments to select a unique key.",
            multiplicity,
            if let Some(controlled_did) = controlled_did_o {
                format!(" DID \"{}\"", controlled_did)
            } else {
                "".to_string()
            },
            if let Some(key_purpose) = key_purpose_o {
                format!(" KeyPurpose \"{}\"", key_purpose)
            } else {
                "".to_string()
            },
            if let Some(key_id) = key_id_o {
                format!(" KeyID \"{}\"", key_id)
            } else {
                "".to_string()
            }
        );
    }
    Ok(query_result_v.into_iter().next().unwrap())
}

// TODO: Technically it's necessary to fetch all DID updates from the VDR to ensure that we use
// a signing key that is actually valid.  But maybe that should be a separate step, and this
// is naturally decomposed.
pub async fn wallet_did_sign_jws(
    payload_bytes: &mut dyn std::io::Read,
    payload_presence: did_webplus_jws::JWSPayloadPresence,
    payload_encoding: did_webplus_jws::JWSPayloadEncoding,
    wallet: &dyn did_webplus_wallet::Wallet,
    controlled_did_o: Option<&did_webplus_core::DIDStr>,
    key_purpose_o: Option<did_webplus_core::KeyPurpose>,
    key_id_o: Option<&selfsign::KERIVerifierStr>,
) -> Result<did_webplus_jws::JWS<'static>> {
    // Get the specified signing key.
    let (verification_method_record, signer_b) =
        wallet_did_select_key(wallet, controlled_did_o, key_purpose_o, key_id_o).await?;
    // Form the kid (key ID).
    let kid = verification_method_record
        .did_key_resource_fully_qualified
        .to_string();

    let jws = did_webplus_jws::JWS::signed(
        kid,
        payload_bytes,
        payload_presence,
        payload_encoding,
        signer_b.as_ref(),
    )?;

    Ok(jws)
}

// TODO: Technically it's necessary to fetch all DID updates from the VDR to ensure that we use
// a signing key that is actually valid.  But maybe that should be a separate step, and this
// is naturally decomposed.
pub async fn wallet_did_sign_vjson(
    value: &mut serde_json::Value,
    wallet: &dyn did_webplus_wallet::Wallet,
    controlled_did_o: Option<&did_webplus_core::DIDStr>,
    key_purpose_o: Option<did_webplus_core::KeyPurpose>,
    key_id_o: Option<&selfsign::KERIVerifierStr>,
    vjson_resolver: &dyn vjson_core::VJSONResolver,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
) -> Result<()> {
    // Get the specified signing key.
    let (verification_method_record, signer_b) =
        wallet_did_select_key(wallet, controlled_did_o, key_purpose_o, key_id_o).await?;
    // Form the kid (key ID).
    let kid = verification_method_record
        .did_key_resource_fully_qualified
        .to_string();

    vjson_core::sign_and_self_hash_vjson(
        value,
        kid,
        signer_b.as_ref(),
        vjson_resolver,
        Some(verifier_resolver),
    )
    .await?;

    Ok(())
}

pub async fn wallet_list<Storage: did_webplus_wallet_store::WalletStorage>(
    wallet_storage: Storage,
    wallet_record_filter: &did_webplus_wallet_store::WalletRecordFilter,
) -> Result<Vec<did_webplus_wallet_store::WalletRecord>> {
    let mut transaction = wallet_storage.begin_transaction(None).await?;
    let wallet_record_v = wallet_storage
        .get_wallets(&mut transaction, wallet_record_filter)
        .await?
        .into_iter()
        .map(|(_ctx, wallet_record)| wallet_record)
        .collect::<Vec<_>>();
    wallet_storage.commit_transaction(transaction).await?;
    Ok(wallet_record_v)
}
