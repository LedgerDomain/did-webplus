pub use anyhow::Result;

pub fn private_key_generate(
    key_type: signature_dyn::KeyType,
) -> Box<dyn signature_dyn::SignerDynT> {
    key_type.generate_random_private_key()
}

/// Determine the did:key representation of the public key corresponding to this private key.
pub fn did_key_from_private(signer: &dyn signature_dyn::SignerDynT) -> Result<did_key::DID> {
    Ok(did_key::DID::try_from(&signer.verifier_bytes()?)?)
}

/// PKCS8 is a standard format for representing cryptographic keys, e.g. for storing in a file.
// TODO: Make a browser-specific version of this that writes to some appropriate kind of browser storage.
pub fn private_key_write_to_pkcs8_pem_file(
    signer_pkcs8: &dyn signature_dyn::PKCS8Write,
    private_key_path: &std::path::Path,
) -> Result<()> {
    signer_pkcs8
        .write_to_pkcs8_pem_file(private_key_path)
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to write private key to {:?}; error was: {}",
                private_key_path,
                e
            )
        })?;
    Ok(())
}

/// PKCS8 is a standard format for representing cryptographic keys, e.g. for storing in a file.
// TODO: Make a browser-specific version of this that writes to some appropriate kind of browser storage.
pub fn private_key_read_from_pkcs8_pem_file(
    private_key_path: &std::path::Path,
) -> Result<Box<dyn signature_dyn::SignerDynT>> {
    use signature_dyn::PKCS8Read;
    // This is a bit of a hack.  It would be better to somehow determine the key type first,
    // then invoke the correct read function.
    for &key_type in signature_dyn::KEY_TYPE_V {
        match key_type {
            signature_dyn::KeyType::Ed25519 => {
                #[cfg(feature = "ed25519-dalek")]
                if let Ok(signing_key) =
                    ed25519_dalek::SigningKey::read_from_pkcs8_pem_file(&private_key_path)
                {
                    return Ok(Box::new(signing_key));
                }
            }
            signature_dyn::KeyType::Ed448 => {
                #[cfg(feature = "ed448-goldilocks")]
                {
                    if let Ok(signing_key) =
                        ed448_goldilocks::SigningKey::read_from_pkcs8_pem_file(&private_key_path)
                    {
                        return Ok(Box::new(signing_key));
                    }
                }
            }
            signature_dyn::KeyType::P256 => {
                #[cfg(feature = "p256")]
                if let Ok(signing_key) =
                    p256::ecdsa::SigningKey::read_from_pkcs8_pem_file(&private_key_path)
                {
                    return Ok(Box::new(signing_key));
                }
            }
            signature_dyn::KeyType::P384 => {
                #[cfg(feature = "p384")]
                if let Ok(signing_key) =
                    p384::ecdsa::SigningKey::read_from_pkcs8_pem_file(&private_key_path)
                {
                    return Ok(Box::new(signing_key));
                }
            }
            signature_dyn::KeyType::P521 => {
                #[cfg(feature = "p521")]
                if let Ok(signing_key) =
                    p521::ecdsa::SigningKey::read_from_pkcs8_pem_file(&private_key_path)
                {
                    return Ok(Box::new(signing_key));
                }
            }
            signature_dyn::KeyType::Secp256k1 => {
                #[cfg(feature = "k256")]
                if let Ok(signing_key) =
                    k256::ecdsa::SigningKey::read_from_pkcs8_pem_file(&private_key_path)
                {
                    return Ok(Box::new(signing_key));
                }
            }
            _ => {}
        }
    }
    anyhow::bail!(
        "Private key at path {:?} was not in a recognized format.",
        private_key_path.to_str().unwrap()
    );
}

pub fn did_key_sign_jws(
    payload_bytes: &mut dyn std::io::Read,
    payload_presence: did_webplus_jws::JWSPayloadPresence,
    payload_encoding: did_webplus_jws::JWSPayloadEncoding,
    signer: &dyn signature_dyn::SignerDynT,
) -> Result<did_webplus_jws::JWS<'static>> {
    let did_resource = did_key::DIDResource::try_from(&signer.verifier_bytes()?)?;
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
    signer: &dyn signature_dyn::SignerDynT,
    vjson_resolver: &dyn vjson_core::VJSONResolver,
) -> Result<mbx::MBHash> {
    let did_resource = did_key::DIDResource::try_from(&signer.verifier_bytes()?)?;
    let kid = did_resource.to_string();
    let verifier_resolver = did_key::DIDKeyVerifierResolver;
    Ok(vjson_core::sign_and_self_hash_vjson(
        value,
        kid,
        signer,
        vjson_resolver,
        Some(&verifier_resolver),
    )
    .await?)
}

// TODO: Rename this function to something more appropriate
pub async fn did_list(
    did_doc_storage: &dyn did_webplus_doc_store::DIDDocStorage,
    did_doc_record_filter: &did_webplus_doc_store::DIDDocRecordFilter,
) -> Result<Vec<did_webplus_doc_store::DIDDocRecord>> {
    let mut transaction_b = did_doc_storage.begin_transaction().await?;
    let did_doc_record_v = did_doc_storage
        .get_did_doc_records(Some(transaction_b.as_mut()), &did_doc_record_filter)
        .await?;
    transaction_b.commit().await?;
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
    use selfhash::{HashFunctionT, SelfHashableT};
    let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);
    self_hashable_json
        .self_hash(mb_hash_function.new_hasher())
        .expect("self-hash failed");

    // Verify the self-hash.  This is mostly a sanity check.
    self_hashable_json
        .verify_self_hashes()
        .expect("programmer error: self-hash verification failed");

    Ok(self_hashable_json.into_value())
}

// NOTE: There's almost no point to this function except to make it known in the same place as the others.
pub async fn vjson_store_add_str(
    vjson_str: &str,
    vjson_store: &vjson_store::VJSONStore,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
    already_exists_policy: vjson_store::AlreadyExistsPolicy,
) -> Result<()> {
    vjson_store
        .add_vjson_str(None, vjson_str, verifier_resolver, already_exists_policy)
        .await?;
    Ok(())
}

// NOTE: There's almost no point to this function except to make it known in the same place as the others.
pub async fn vjson_store_add_value(
    vjson_value: &serde_json::Value,
    vjson_store: &vjson_store::VJSONStore,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
    already_exists_policy: vjson_store::AlreadyExistsPolicy,
) -> Result<()> {
    vjson_store
        .add_vjson_value(None, vjson_value, verifier_resolver, already_exists_policy)
        .await?;
    Ok(())
}

// NOTE: There's almost no point to this function except to make it known in the same place as the others.
pub async fn vjson_store_get_value(
    self_hash: &mbx::MBHashStr,
    vjson_store: &vjson_store::VJSONStore,
) -> Result<serde_json::Value> {
    // Retrieve the specified VJSON value from the VJSON store.  This guarantees it's valid.
    Ok(vjson_store.get_vjson_value(None, self_hash).await?)
}

// NOTE: There's almost no point to this function except to make it known in the same place as the others.
pub async fn vjson_store_get_record(
    self_hash: &mbx::MBHashStr,
    vjson_store: &vjson_store::VJSONStore,
) -> Result<vjson_store::VJSONRecord> {
    // Retrieve the specified VJSONRecord from the VJSON store.  This guarantees the VJSON is valid.
    Ok(vjson_store.get_vjson_record(None, &self_hash).await?)
}

pub async fn vjson_verify(
    value: &serde_json::Value,
    vjson_resolver: &dyn vjson_core::VJSONResolver,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
) -> Result<mbx::MBHash> {
    use vjson_core::Validate;
    let self_hash = value
        .validate_and_return_self_hash(vjson_resolver, verifier_resolver)
        .await?;
    Ok(self_hash)
}

pub async fn wallet_did_create(
    wallet: &dyn did_webplus_wallet::Wallet,
    vdr_did_create_endpoint: &str,
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
) -> Result<did_webplus_core::DIDFullyQualified> {
    Ok(wallet
        .create_did(vdr_did_create_endpoint, http_scheme_override_o)
        .await?)
}

pub async fn wallet_did_update(
    wallet: &dyn did_webplus_wallet::Wallet,
    did: &did_webplus_core::DIDStr,
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
) -> Result<did_webplus_core::DIDFullyQualified> {
    Ok(wallet.update_did(&did, http_scheme_override_o).await?)
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
    key_id_o: Option<&str>,
) -> Result<(
    did_webplus_wallet_store::VerificationMethodRecord,
    signature_dyn::SignerBytes<'static>,
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
    key_id_o: Option<&str>,
) -> Result<did_webplus_jws::JWS<'static>> {
    // Get the specified signing key.
    let (verification_method_record, signer_bytes) =
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
        &signer_bytes,
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
    key_id_o: Option<&str>,
    vjson_resolver: &dyn vjson_core::VJSONResolver,
    verifier_resolver: &dyn verifier_resolver::VerifierResolver,
) -> Result<mbx::MBHash> {
    // Get the specified signing key.
    let (verification_method_record, signer_bytes) =
        wallet_did_select_key(wallet, controlled_did_o, key_purpose_o, key_id_o).await?;
    // Form the kid (key ID).
    let kid = verification_method_record
        .did_key_resource_fully_qualified
        .to_string();

    Ok(vjson_core::sign_and_self_hash_vjson(
        value,
        kid,
        &signer_bytes,
        vjson_resolver,
        Some(verifier_resolver),
    )
    .await?)
}

pub async fn wallet_list(
    wallet_storage: &dyn did_webplus_wallet_store::WalletStorage,
    wallet_record_filter: &did_webplus_wallet_store::WalletRecordFilter,
) -> Result<Vec<did_webplus_wallet_store::WalletRecord>> {
    let mut transaction_b = wallet_storage.begin_transaction().await?;
    let wallet_record_v = wallet_storage
        .get_wallets(Some(transaction_b.as_mut()), wallet_record_filter)
        .await?
        .into_iter()
        .map(|(_ctx, wallet_record)| wallet_record)
        .collect::<Vec<_>>();
    transaction_b.commit().await?;
    Ok(wallet_record_v)
}
