use std::{collections::HashMap, sync::Arc};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

/// Integration test for DIDResolverFull operating against a VDR, but without a VDG.
#[tokio::test(flavor = "multi_thread")]
async fn test_did_resolver() {
    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    // TODO: postgres drop schema

    let vdg_listen_port = 50001;
    let vdg_config = did_webplus_vdg_lib::VDGConfig {
        listen_port: vdg_listen_port,
        database_url: "postgres:///test_did_resolver_vdg".to_string(),
        database_max_connections: 10,
        http_scheme_override: Default::default(),
    };
    let vdg_handle = did_webplus_vdg_lib::spawn_vdg(vdg_config.clone())
        .await
        .expect("pass");
    let vdg_host = format!("localhost:{}", vdg_config.listen_port);
    let vdg_base_url = url::Url::parse(&format!("http://{}", vdg_host)).expect("pass");

    let vdr_listen_port = 50000;
    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(vdr_listen_port),
        listen_port: vdr_listen_port,
        database_url: "postgres:///test_did_resolver_vdr".to_string(),
        database_max_connections: 10,
        vdg_base_url_v: vec![vdg_base_url.clone()],
        http_scheme_override: Default::default(),
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");
    let vdr_url =
        url::Url::parse(&format!("http://localhost:{}", vdr_config.listen_port)).expect("pass");

    test_util::wait_until_service_is_up("VDG", vdg_base_url.join("health").expect("pass").as_str())
        .await;
    tracing::info!("VDG is up");
    test_util::wait_until_service_is_up("VDR", vdr_url.join("health").expect("pass").as_str())
        .await;
    tracing::info!("VDR is up");

    //
    // Now that the VDR is up, create a DID and verify that it can be resolved.
    //

    // Create an in-memory SoftwareWallet.
    let (wallet_storage_a, software_wallet) = {
        let sqlite_pool = sqlx::SqlitePool::connect("sqlite://:memory:")
            .await
            .expect("pass");
        let wallet_storage_a = Arc::new(
            did_webplus_wallet_storage_sqlite::WalletStorageSQLite::open_and_run_migrations(
                sqlite_pool,
            )
            .await
            .expect("pass"),
        );
        use storage_traits::StorageDynT;
        let mut transaction_b = wallet_storage_a.begin_transaction().await.expect("pass");
        let software_wallet = did_webplus_software_wallet::SoftwareWallet::create(
            transaction_b.as_mut(),
            wallet_storage_a.clone(),
            Some("Test wallet for test_did_resolver".to_string()),
            None,
        )
        .await
        .expect("pass");
        transaction_b.commit().await.expect("pass");

        (wallet_storage_a, software_wallet)
    };

    // Create a DID.
    use did_webplus_wallet::Wallet;
    let mut controlled_did = software_wallet
        .create_did(vdr_url.as_str(), None)
        .await
        .expect("pass");
    let did = controlled_did.did().to_owned();
    tracing::info!("Created DID: {} (fully qualified: {})", did, controlled_did);

    // Create DIDResolverFull for having a VDG host and not.
    let did_resolver_full_m = {
        let mut did_resolver_full_m = HashMap::with_capacity(2);
        for vdg_host_o in [None, Some(vdg_host.clone())] {
            let sqlite_pool = sqlx::SqlitePool::connect("sqlite://:memory:")
                .await
                .expect("pass");
            let did_doc_storage =
                did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(
                    sqlite_pool,
                )
                .await
                .expect("pass");
            let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage));
            let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
                did_doc_store,
                vdg_host_o.as_deref(),
                None,
            )
            .unwrap();
            did_resolver_full_m.insert(vdg_host_o, did_resolver_full);
        }
        did_resolver_full_m
    };

    // Now update it many times.
    // const UPDATE_COUNT: usize = 2000;
    let big_update_count = std::env::var("UPDATE_COUNT")
        .unwrap_or("10".to_string())
        .parse::<usize>()
        .unwrap();

    for update_count in [big_update_count, 1, 0] {
        tracing::info!("Updating DID {} times", update_count);
        // Start a timer just to see how long it takes to create the DID and update it many times.
        let time_start = std::time::SystemTime::now();
        for _ in 0..update_count {
            controlled_did = software_wallet.update_did(&did, None).await.expect("pass");
        }
        // Stop the timer.
        let duration = std::time::SystemTime::now()
            .duration_since(time_start)
            .expect("pass");
        tracing::info!(
            "-- Time taken to update DID {} times: {:?} -------------------------",
            update_count,
            duration
        );

        // Retrieve the latest DID doc from the wallet's doc store.  This will be a sanity check for the performance test.
        let expected_latest_did_document_jcs = {
            use did_webplus_wallet_store::WalletStorage;
            let did_doc_record = wallet_storage_a
                .as_did_doc_storage()
                .get_latest_did_doc_record(None, controlled_did.did())
                .await
                .expect("pass")
                .expect("pass");
            did_doc_record.did_document_jcs
        };

        let mut timing_result_v = Vec::with_capacity(4);
        for vdg_host_o in [None, Some(vdg_host.clone())] {
            let did_resolver_full = did_resolver_full_m.get(&vdg_host_o).expect("pass");

            // Start the timer
            let time_start = std::time::SystemTime::now();

            // Resolve the DID.
            use did_webplus_resolver::DIDResolver;
            let (did_document_body, _did_document_metadata) = did_resolver_full
                .resolve_did_document_string(
                    &did,
                    did_webplus_core::RequestedDIDDocumentMetadata::none(),
                )
                .await
                .expect("pass");

            // Stop the timer.
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::debug!("Time taken: {:?}", duration);
            timing_result_v.push((
                format!("DIDResolverFull {{ vdg_host_o: {:?} }}", vdg_host_o),
                duration,
            ));

            // Verify that the DID document body is the expected value.
            assert_eq!(did_document_body, expected_latest_did_document_jcs);
        }

        // Now to test DIDResolverThin:
        {
            let did_resolver_thin =
                did_webplus_resolver::DIDResolverThin::new(&vdg_host, None).expect("pass");

            // Start the timer
            let time_start = std::time::SystemTime::now();

            // Resolve the DID.
            use did_webplus_resolver::DIDResolver;
            let (did_document_body, _did_document_metadata) = did_resolver_thin
                .resolve_did_document_string(
                    &did,
                    did_webplus_core::RequestedDIDDocumentMetadata::none(),
                )
                .await
                .expect("pass");

            // Stop the timer.
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::debug!("Time taken: {:?}", duration);
            timing_result_v.push(("DIDResolverThin".to_string(), duration));

            // Verify that the DID document body is the expected value.
            assert_eq!(did_document_body, expected_latest_did_document_jcs);
        }

        // Print the timing results.
        for (resolver_name, duration) in timing_result_v {
            tracing::info!("{}: Time taken: {:?}", resolver_name, duration);
        }
    }

    //
    // Tests are done, so shut down.
    //

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
    tracing::info!("Shutting down VDG");
    vdg_handle.abort();
}
