use std::sync::Arc;

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

async fn test_did_key_generate_write_read_sign_jws_verify_impl(key_type: selfsign::KeyType) {
    let private_key_path = std::path::PathBuf::from(format!(
        "tests/test_did_key_generate_write_read_sign_jws_verify.{:?}.priv.pem",
        key_type
    ));
    if std::fs::exists(&private_key_path).unwrap() {
        std::fs::remove_file(&private_key_path).unwrap();
    }

    let signer_b = did_webplus_cli_lib::private_key_generate(key_type);
    let did = did_webplus_cli_lib::did_key_from_private(signer_b.as_ref()).expect("pass");
    did_webplus_cli_lib::private_key_write_to_pkcs8_pem_file(signer_b.as_ref(), &private_key_path)
        .expect("pass");

    let read_signer_b =
        did_webplus_cli_lib::private_key_read_from_pkcs8_pem_file(&private_key_path).expect("pass");
    let read_did = did_webplus_cli_lib::did_key_from_private(read_signer_b.as_ref()).expect("pass");
    // Check that the DIDs and the signers are the same.
    assert_eq!(read_did, did);
    assert_eq!(
        read_signer_b.to_private_key_bytes(),
        signer_b.to_private_key_bytes()
    );

    let payload = r#"{"blah": 123}"#;
    // Sign and then verify an attached-payload JWS
    {
        let jws = did_webplus_cli_lib::did_key_sign_jws(
            &mut payload.as_bytes(),
            did_webplus_jws::JWSPayloadPresence::Attached,
            did_webplus_jws::JWSPayloadEncoding::Base64,
            signer_b.as_ref(),
        )
        .expect("pass");
        did_webplus_cli_lib::jws_verify(&jws, None, &did_key::DIDKeyVerifierResolver)
            .await
            .expect("pass");
    }
    // Sign and then verify a detached-payload JWS
    {
        let jws = did_webplus_cli_lib::did_key_sign_jws(
            &mut payload.as_bytes(),
            did_webplus_jws::JWSPayloadPresence::Detached,
            did_webplus_jws::JWSPayloadEncoding::Base64,
            signer_b.as_ref(),
        )
        .expect("pass");
        did_webplus_cli_lib::jws_verify(
            &jws,
            Some(&mut payload.as_bytes()),
            &did_key::DIDKeyVerifierResolver,
        )
        .await
        .expect("pass");
    }
}

#[tokio::test]
async fn test_did_key_generate_write_read_sign_jws_verify_ed25519() {
    test_did_key_generate_write_read_sign_jws_verify_impl(selfsign::KeyType::Ed25519).await;
}

#[tokio::test]
async fn test_did_key_generate_write_read_sign_jws_verify_secp256k1() {
    test_did_key_generate_write_read_sign_jws_verify_impl(selfsign::KeyType::Secp256k1).await;
}

async fn test_did_key_sign_vjson_verify_impl(key_type: selfsign::KeyType) {
    let private_key_path = std::path::PathBuf::from(format!(
        "tests/test_did_key_sign_vjson_verify.{:?}.priv.pem",
        key_type
    ));
    let vjson_store_database_path = std::path::PathBuf::from(format!(
        "tests/test_did_key_sign_vjson_verify.{:?}.vjson-store.db",
        key_type
    ));

    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to drop and recreate the relevant databases.
    if std::fs::exists(&private_key_path).unwrap() {
        std::fs::remove_file(&private_key_path).unwrap();
    }
    if std::fs::exists(&vjson_store_database_path).expect("pass") {
        std::fs::remove_file(&vjson_store_database_path).expect("pass");
    }

    let signer_b = did_webplus_cli_lib::private_key_generate(key_type);

    let vjson_store = {
        let sqlite_pool = sqlx::SqlitePool::connect(
            format!(
                "sqlite://{}?mode=rwc",
                vjson_store_database_path.to_str().unwrap()
            )
            .as_str(),
        )
        .await
        .expect("pass");
        let vjson_storage =
            vjson_storage_sqlite::VJSONStorageSQLite::open_and_run_migrations(sqlite_pool)
                .await
                .expect("pass");
        vjson_store::VJSONStore::new(Arc::new(vjson_storage))
            .await
            .expect("pass")
    };

    let verifier_resolver = &did_key::DIDKeyVerifierResolver;

    let mut price_quote_schema = price_quote_schema();
    // Sign
    let price_quote_schema_self_hash = did_webplus_cli_lib::did_key_sign_vjson(
        &mut price_quote_schema,
        signer_b.as_ref(),
        &vjson_store,
    )
    .await
    .expect("pass");
    tracing::debug!(
        "price_quote_schema: {}",
        serde_json::to_string_pretty(&price_quote_schema).unwrap()
    );
    // Verify
    did_webplus_cli_lib::vjson_verify(&price_quote_schema, &vjson_store, verifier_resolver)
        .await
        .expect("pass");
    // Store
    {
        use storage_traits::StorageDynT;
        let mut transaction_b = vjson_store.begin_transaction().await.expect("pass");
        vjson_store
            .add_vjson_value(
                Some(transaction_b.as_mut()),
                &price_quote_schema,
                verifier_resolver,
                vjson_store::AlreadyExistsPolicy::Fail,
            )
            .await
            .expect("pass");
        transaction_b.commit().await.expect("pass");
    }

    let mut price_quote = price_quote(
        &price_quote_schema_self_hash,
        "A fancy, fancy rock",
        "6,000,000 USD",
    );
    let _price_quote_self_hash =
        did_webplus_cli_lib::did_key_sign_vjson(&mut price_quote, signer_b.as_ref(), &vjson_store)
            .await
            .expect("pass");
    tracing::debug!(
        "price_quote: {}",
        serde_json::to_string_pretty(&price_quote).unwrap()
    );
    // Verify
    did_webplus_cli_lib::vjson_verify(&price_quote, &vjson_store, &did_key::DIDKeyVerifierResolver)
        .await
        .expect("pass");
    // Store
    {
        use storage_traits::StorageDynT;
        let mut transaction_b = vjson_store.begin_transaction().await.expect("pass");
        vjson_store
            .add_vjson_value(
                Some(transaction_b.as_mut()),
                &price_quote,
                verifier_resolver,
                vjson_store::AlreadyExistsPolicy::Fail,
            )
            .await
            .expect("pass");
        transaction_b.commit().await.expect("pass");
    }
}

#[tokio::test]
async fn test_did_key_sign_vjson_verify_ed25519_dalek() {
    test_did_key_sign_vjson_verify_impl(selfsign::KeyType::Ed25519).await;
}

#[tokio::test]
async fn test_did_key_sign_vjson_verify_k256() {
    test_did_key_sign_vjson_verify_impl(selfsign::KeyType::Secp256k1).await;
}

fn price_quote_schema() -> serde_json::Value {
    serde_json::json!(
        {
            "$id": "vjson:///",
            "type": "object",
            "title": "PriceQuote",
            "properties": {
                "$schema": {
                    "type": "string",
                    "description": "The schema that this JSON must adhere to."
                },
                "item": {
                    "type": "string",
                    "description": "A description of the item whose price is being quoted."
                },
                "price": {
                    "type": "string",
                    "description": "The price of the item."
                },
                "proofs": {
                    "type": "array",
                    "description": "Array of detached JSON Web Signatures (JWS) over the VJSON."
                },
                "selfHash": {
                    "type": "string",
                    "description": "Uniquely identifies this particular PriceQuote."
                }
            },
            "required": [
                "$schema",
                "item",
                "price",
                "selfHash"
            ],
            "additionalProperties": false,
            "vjsonProperties": {
                "directDependencies": [
                    "$.$schema"
                ],
                "mustBeSigned": false,
                "selfHashPaths": [
                    "$.selfHash"
                ],
                "selfHashURLPaths": []
            }
        }
    )
}

fn price_quote(
    schema_self_hash: &selfhash::KERIHashStr,
    item: &str,
    price: &str,
) -> serde_json::Value {
    serde_json::json!(
        {
            "$schema": format!("vjson:///{}", schema_self_hash),
            "item": item,
            "price": price
        }
    )
}

#[tokio::test]
async fn test_wallet_did_create_update_sign_jws_verify() {
    // TODO: Use env vars to be able to point to a "real" VDR.

    let wallet_store_database_path =
        "tests/test_wallet_did_create_update_sign_jws_verify.wallet-store.db";
    let did_doc_store_database_path =
        "tests/test_wallet_did_create_update_sign_jws_verify.did-doc-store.db";

    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    // TODO: postgres drop schema
    if std::fs::exists(wallet_store_database_path).expect("pass") {
        std::fs::remove_file(wallet_store_database_path).expect("pass");
    }
    if std::fs::exists(did_doc_store_database_path).expect("pass") {
        std::fs::remove_file(did_doc_store_database_path).expect("pass");
    }

    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(12085),
        listen_port: 12085,
        // database_url: format!("sqlite://{}?mode=rwc", vdr_database_path),
        database_url: "postgres:///test_wallet_did_create_update_sign_jws_verify_vdr".to_string(),
        database_max_connections: 10,
        gateway_url_v: Vec::new(),
        http_scheme_override: Default::default(),
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");

    let http_scheme_override_o = None;
    let vdr_scheme = did_webplus_core::HTTPSchemeOverride::determine_http_scheme_for_hostname_from(
        http_scheme_override_o,
        &vdr_config.did_hostname,
    );
    let vdr_did_create_endpoint = format!(
        "{}://{}:{}",
        vdr_scheme, vdr_config.did_hostname, vdr_config.listen_port
    );

    let wallet_storage = {
        let sqlite_pool = sqlx::SqlitePool::connect(
            format!("sqlite://{}?mode=rwc", wallet_store_database_path).as_str(),
        )
        .await
        .expect("pass");
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(sqlite_pool)
            .await
            .expect("pass")
    };
    let wallet_storage_a = Arc::new(wallet_storage);

    let did_resolver_full = {
        let sqlite_pool = sqlx::SqlitePool::connect(
            format!("sqlite://{}?mode=rwc", did_doc_store_database_path).as_str(),
        )
        .await
        .expect("pass");
        let did_doc_storage =
            did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(
                sqlite_pool,
            )
            .await
            .expect("pass");
        let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
        did_webplus_resolver::DIDResolverFull {
            did_doc_store,
            http_scheme_override_o: http_scheme_override_o.cloned(),
        }
    };

    use storage_traits::StorageDynT;
    let mut transaction_b = wallet_storage_a.begin_transaction().await.expect("pass");
    let software_wallet = did_webplus_software_wallet::SoftwareWallet::create(
        transaction_b.as_mut(),
        wallet_storage_a,
        Some("created by test_wallet_did_create_update_sign_jws_verify".to_string()),
    )
    .await
    .expect("pass");
    transaction_b.commit().await.expect("pass");

    test_util::wait_until_service_is_up(
        "VDR",
        format!("http://localhost:{}/health", vdr_config.listen_port).as_str(),
    )
    .await;

    let controlled_did = did_webplus_cli_lib::wallet_did_create(
        &software_wallet,
        &vdr_did_create_endpoint,
        http_scheme_override_o,
    )
    .await
    .expect("pass");
    let did = controlled_did.did();
    tracing::debug!("created DID: {} - fully qualified: {}", did, controlled_did);

    let controlled_did =
        did_webplus_cli_lib::wallet_did_update(&software_wallet, did, http_scheme_override_o)
            .await
            .expect("pass");
    tracing::debug!("updated DID: {} - fully qualified: {}", did, controlled_did);

    let payload = r#"{"splunge": true}"#;
    // Sign and then verify an attached-payload JWS
    {
        let jws = did_webplus_cli_lib::wallet_did_sign_jws(
            &mut payload.as_bytes(),
            did_webplus_jws::JWSPayloadPresence::Attached,
            did_webplus_jws::JWSPayloadEncoding::Base64,
            &software_wallet,
            Some(did),
            Some(did_webplus_core::KeyPurpose::AssertionMethod),
            None,
        )
        .await
        .expect("pass");
        did_webplus_cli_lib::jws_verify(&jws, None, &did_resolver_full)
            .await
            .expect("pass");
    }
    // Sign and then verify a detached-payload JWS
    {
        let jws = did_webplus_cli_lib::wallet_did_sign_jws(
            &mut payload.as_bytes(),
            did_webplus_jws::JWSPayloadPresence::Detached,
            did_webplus_jws::JWSPayloadEncoding::Base64,
            &software_wallet,
            Some(did),
            Some(did_webplus_core::KeyPurpose::AssertionMethod),
            None,
        )
        .await
        .expect("pass");
        did_webplus_cli_lib::jws_verify(&jws, Some(&mut payload.as_bytes()), &did_resolver_full)
            .await
            .expect("pass");
    }

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}

#[tokio::test]
async fn test_wallet_did_sign_vjson_verify() {
    // TODO: Use env vars to be able to point to a "real" VDR.

    let wallet_store_database_path = "tests/test_wallet_did_sign_vjson_verify.wallet-store.db";
    let did_doc_store_database_path = "tests/test_wallet_did_sign_vjson_verify.did-doc-store.db";
    let vjson_store_database_path = "tests/test_wallet_did_sign_vjson_verify.vjson-store.db";

    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    // TODO: postgres drop schema
    if std::fs::exists(wallet_store_database_path).expect("pass") {
        std::fs::remove_file(wallet_store_database_path).expect("pass");
    }
    if std::fs::exists(did_doc_store_database_path).expect("pass") {
        std::fs::remove_file(did_doc_store_database_path).expect("pass");
    }
    if std::fs::exists(vjson_store_database_path).expect("pass") {
        std::fs::remove_file(vjson_store_database_path).expect("pass");
    }

    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(13085),
        listen_port: 13085,
        database_url: "postgres:///test_wallet_did_sign_vjson_verify_vdr".to_string(),
        database_max_connections: 10,
        gateway_url_v: Vec::new(),
        http_scheme_override: Default::default(),
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");

    let http_scheme_override_o = None;
    let vdr_scheme = did_webplus_core::HTTPSchemeOverride::determine_http_scheme_for_hostname_from(
        http_scheme_override_o,
        &vdr_config.did_hostname,
    );
    let vdr_did_create_endpoint = format!(
        "{}://{}:{}",
        vdr_scheme, vdr_config.did_hostname, vdr_config.listen_port
    );

    let wallet_storage = {
        let sqlite_pool = sqlx::SqlitePool::connect(
            format!("sqlite://{}?mode=rwc", wallet_store_database_path).as_str(),
        )
        .await
        .expect("pass");
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(sqlite_pool)
            .await
            .expect("pass")
    };
    let wallet_storage_a = Arc::new(wallet_storage);

    let did_resolver_full = {
        let sqlite_pool = sqlx::SqlitePool::connect(
            format!("sqlite://{}?mode=rwc", did_doc_store_database_path).as_str(),
        )
        .await
        .expect("pass");
        let did_doc_storage =
            did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(
                sqlite_pool,
            )
            .await
            .expect("pass");
        let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
        did_webplus_resolver::DIDResolverFull {
            did_doc_store,
            http_scheme_override_o: http_scheme_override_o.cloned(),
        }
    };

    use storage_traits::StorageDynT;
    let mut transaction_b = wallet_storage_a.begin_transaction().await.expect("pass");
    let software_wallet = did_webplus_software_wallet::SoftwareWallet::create(
        transaction_b.as_mut(),
        wallet_storage_a,
        Some("created by test_wallet_did_sign_vjson_verify".to_string()),
    )
    .await
    .expect("pass");
    transaction_b.commit().await.expect("pass");

    test_util::wait_until_service_is_up(
        "VDR",
        format!("http://localhost:{}/health", vdr_config.listen_port).as_str(),
    )
    .await;

    let controlled_did = did_webplus_cli_lib::wallet_did_create(
        &software_wallet,
        &vdr_did_create_endpoint,
        http_scheme_override_o,
    )
    .await
    .expect("pass");
    let did = controlled_did.did();
    tracing::debug!("created DID: {} - fully qualified: {}", did, controlled_did);

    let vjson_store = {
        let sqlite_pool = sqlx::SqlitePool::connect(
            format!("sqlite://{}?mode=rwc", vjson_store_database_path).as_str(),
        )
        .await
        .expect("pass");
        let vjson_storage =
            vjson_storage_sqlite::VJSONStorageSQLite::open_and_run_migrations(sqlite_pool)
                .await
                .expect("pass");
        vjson_store::VJSONStore::new(Arc::new(vjson_storage))
            .await
            .expect("pass")
    };

    let mut price_quote_schema = price_quote_schema();
    // Sign
    let price_quote_schema_self_hash = did_webplus_cli_lib::wallet_did_sign_vjson(
        &mut price_quote_schema,
        &software_wallet,
        Some(did),
        Some(did_webplus_core::KeyPurpose::Authentication),
        None,
        &vjson_store,
        &did_resolver_full,
    )
    .await
    .expect("pass");
    tracing::debug!(
        "price_quote_schema: {}",
        serde_json::to_string_pretty(&price_quote_schema).unwrap()
    );
    // Verify
    did_webplus_cli_lib::vjson_verify(&price_quote_schema, &vjson_store, &did_resolver_full)
        .await
        .expect("pass");
    // Store
    {
        use storage_traits::StorageDynT;
        let mut transaction_b = vjson_store.begin_transaction().await.expect("pass");
        vjson_store
            .add_vjson_value(
                Some(transaction_b.as_mut()),
                &price_quote_schema,
                &did_resolver_full,
                vjson_store::AlreadyExistsPolicy::Fail,
            )
            .await
            .expect("pass");
        transaction_b.commit().await.expect("pass");
    }

    let mut price_quote = price_quote(
        &price_quote_schema_self_hash,
        "A fancy, fancy rock",
        "6,000,000 USD",
    );
    let _price_quote_self_hash = did_webplus_cli_lib::wallet_did_sign_vjson(
        &mut price_quote,
        &software_wallet,
        Some(did),
        Some(did_webplus_core::KeyPurpose::Authentication),
        None,
        &vjson_store,
        &did_resolver_full,
    )
    .await
    .expect("pass");
    tracing::debug!(
        "price_quote: {}",
        serde_json::to_string_pretty(&price_quote).unwrap()
    );
    // Verify
    did_webplus_cli_lib::vjson_verify(&price_quote, &vjson_store, &did_resolver_full)
        .await
        .expect("pass");
    // Store
    {
        use storage_traits::StorageDynT;
        let mut transaction_b = vjson_store.begin_transaction().await.expect("pass");
        vjson_store
            .add_vjson_value(
                Some(transaction_b.as_mut()),
                &price_quote,
                &did_resolver_full,
                vjson_store::AlreadyExistsPolicy::Fail,
            )
            .await
            .expect("pass");
        transaction_b.commit().await.expect("pass");
    }

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}
