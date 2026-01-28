use std::sync::Arc;

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

async fn test_software_wallet_impl(software_wallet: &did_webplus_software_wallet::SoftwareWallet) {
    // TODO: Use env vars to be able to point to a "real" VDR.

    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    // TODO: postgres drop schema

    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(11085),
        listen_port: 11085,
        database_url: "postgres:///test_software_wallet_vdr".to_string(),
        database_max_connections: 10,
        vdg_base_url_v: Vec::new(),
        http_scheme_override: Default::default(),
        test_authz_api_key_vo: None,
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");

    test_util::wait_until_service_is_up(
        "VDR",
        format!("http://localhost:{}/health", vdr_config.listen_port).as_str(),
    )
    .await;

    let http_headers_for = did_webplus_core::HTTPHeadersFor::new();
    let http_scheme_override = did_webplus_core::HTTPSchemeOverride::new()
        .with_override(vdr_config.did_hostname.clone(), "http")
        .unwrap();
    let http_options = did_webplus_core::HTTPOptions {
        http_headers_for,
        http_scheme_override,
    };
    let vdr_scheme = http_options
        .http_scheme_override
        .determine_http_scheme_for_host(&vdr_config.did_hostname)
        .unwrap();
    let vdr_did_create_endpoint = format!(
        "{}://{}:{}",
        vdr_scheme, vdr_config.did_hostname, vdr_config.listen_port
    );

    for &base in &[mbx::Base::Base58Btc, mbx::Base::Base64Url] {
        for mb_hash_function in &[
            selfhash::MBHashFunction::blake3(base),
            // selfhash::MBHashFunction::sha224(base),
            selfhash::MBHashFunction::sha256(base),
            // selfhash::MBHashFunction::sha384(base),
            selfhash::MBHashFunction::sha512(base),
            // selfhash::MBHashFunction::sha3_224(base),
            selfhash::MBHashFunction::sha3_256(base),
            // selfhash::MBHashFunction::sha3_384(base),
            // selfhash::MBHashFunction::sha3_512(base),
        ] {
            tracing::info!("Testing with mb_hash_function: {:?}", mb_hash_function);

            use did_webplus_wallet::Wallet;
            let controlled_did = software_wallet
                .create_did(
                    did_webplus_wallet::CreateDIDParameters {
                        vdr_did_create_endpoint: vdr_did_create_endpoint.as_str(),
                        mb_hash_function_for_did: &mb_hash_function,
                        mb_hash_function_for_update_key_o: Some(&mb_hash_function),
                    },
                    Some(&http_options),
                )
                .await
                .expect("pass");
            let did = controlled_did.did();
            tracing::debug!("created DID: {} - fully qualified: {}", did, controlled_did);

            let controlled_did = software_wallet
                .update_did(
                    did_webplus_wallet::UpdateDIDParameters {
                        did: &did,
                        change_mb_hash_function_for_self_hash_o: None,
                        mb_hash_function_for_update_key_o: Some(&mb_hash_function),
                    },
                    Some(&http_options),
                )
                .await
                .expect("pass");
            tracing::debug!("updated DID: {} - fully qualified: {}", did, controlled_did);

            let deactivated_did = software_wallet
                .deactivate_did(
                    did_webplus_wallet::DeactivateDIDParameters {
                        did: &did,
                        change_mb_hash_function_for_self_hash_o: None,
                    },
                    Some(&http_options),
                )
                .await
                .expect("pass");
            tracing::debug!(
                "deactivated DID: {} - fully qualified: {}",
                did,
                deactivated_did
            );
        }
    }

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}

#[tokio::test]
#[serial_test::serial]
async fn test_software_wallet_with_storage_sqlite() {
    // TODO: Use env vars to be able to point to a "real" VDR.

    let wallet_store_database_path = "tests/test_software_wallet.wallet-store.db";

    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    if std::fs::exists(wallet_store_database_path).expect("pass") {
        std::fs::remove_file(wallet_store_database_path).expect("pass");
    }

    let sqlite_pool = sqlx::SqlitePool::connect(
        format!("sqlite://{}?mode=rwc", wallet_store_database_path).as_str(),
    )
    .await
    .expect("pass");
    let wallet_storage =
        did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(
            sqlite_pool,
        )
        .await
        .expect("pass");
    let wallet_storage_a = Arc::new(wallet_storage);

    use storage_traits::StorageDynT;
    let mut transaction_b = wallet_storage_a.begin_transaction().await.expect("pass");
    let software_wallet = did_webplus_software_wallet::SoftwareWallet::create(
        transaction_b.as_mut(),
        wallet_storage_a,
        Some("fancy wallet".to_string()),
        None,
    )
    .await
    .expect("pass");
    transaction_b.commit().await.expect("pass");

    test_software_wallet_impl(&software_wallet).await;
}

#[tokio::test]
#[serial_test::serial]
async fn test_software_wallet_with_storage_mock() {
    let wallet_storage = did_webplus_wallet_storage_mock::WalletStorageMock::new();
    let wallet_storage_a = Arc::new(wallet_storage);
    use storage_traits::StorageDynT;
    let mut transaction_b = wallet_storage_a.begin_transaction().await.expect("pass");
    let software_wallet = did_webplus_software_wallet::SoftwareWallet::create(
        transaction_b.as_mut(),
        wallet_storage_a.clone(),
        Some("fancy wallet".to_string()),
        None,
    )
    .await
    .expect("pass");
    transaction_b.commit().await.expect("pass");

    test_software_wallet_impl(&software_wallet).await;
}
