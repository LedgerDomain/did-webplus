use std::sync::Arc;

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

/// Integration test for a URD with a DIDResolverFull operating against a VDR, but without a VDG.
#[tokio::test]
async fn test_urd_with_full_did_resolver_without_vdg() {
    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(60000),
        listen_port: 60000,
        // database_url: format!("sqlite://{}?mode=rwc", vdr_database_path),
        database_url: "postgres:///test_urd_with_full_did_resolver_without_vdg".to_string(),
        database_max_connections: 10,
        vdg_base_url_v: Vec::new(),
        http_scheme_override: Default::default(),
        test_authz_api_key_vo: None,
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");
    let vdr_url = format!("http://localhost:{}", vdr_config.listen_port);

    let urd_listen_port = 60002;
    let urd_did_resolver_full =
        did_webplus_urd_lib::create_did_resolver_full("sqlite://:memory:", None, None, None)
            .await
            .expect("pass");
    let urd_handle =
        did_webplus_urd_lib::spawn_urd(Arc::new(urd_did_resolver_full), urd_listen_port)
            .await
            .expect("pass");
    let urd_url = format!("http://localhost:{}", urd_listen_port);

    test_util::wait_until_service_is_up("VDR", format!("{}/health", vdr_url).as_str()).await;
    test_util::wait_until_service_is_up("URD", format!("{}/health", urd_url).as_str()).await;

    //
    // Now that the URD and VDR are up, create a DID and verify that it can be resolved.
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
            Some("Test wallet for test_urd_with_full_did_resolver_without_vdg".to_string()),
            None,
        )
        .await
        .expect("pass");
        transaction_b.commit().await.expect("pass");

        (wallet_storage_a, software_wallet)
    };

    // Create a DID.
    use did_webplus_wallet::Wallet;
    let controlled_did = software_wallet
        .create_did(&vdr_url, None, None)
        .await
        .expect("pass");
    let did = controlled_did.did();
    tracing::debug!("Created DID: {} (fully qualified: {})", did, controlled_did);

    // Verify that the DID can be resolved via the base DID.
    {
        // Get the latest DID document -- this is the expected value.
        use did_webplus_wallet_store::WalletStorage;
        let did_doc_record = wallet_storage_a
            .as_did_doc_storage()
            .get_latest_known_did_doc_record(None, controlled_did.did())
            .await
            .expect("pass")
            .expect("pass");

        // Resolve the DID via the URD.
        let controlled_did_percent_encoded = percent_encode_did_query(&did);
        let response = test_util::REQWEST_CLIENT
            .get(
                format!(
                    "{}/1.0/identifiers/{}",
                    urd_url, controlled_did_percent_encoded
                )
                .as_str(),
            )
            .send()
            .await
            .expect("pass");
        assert_eq!(response.status(), 200);
        let response_body = response.text().await.expect("pass");
        // Verify that the response body is the expected DID document.
        assert_eq!(response_body, did_doc_record.did_document_jcs);
    }

    // Verify that the DID can be resolved via the fully qualified DID.
    {
        // Get the latest DID document -- this is the expected value.
        use did_webplus_wallet_store::WalletStorage;
        let did_doc_record = wallet_storage_a
            .as_did_doc_storage()
            .get_latest_known_did_doc_record(None, controlled_did.did())
            .await
            .expect("pass")
            .expect("pass");

        // Resolve the DID via the URD.
        let controlled_did_percent_encoded = percent_encode_did_query(&controlled_did);
        let response = test_util::REQWEST_CLIENT
            .get(
                format!(
                    "{}/1.0/identifiers/{}",
                    urd_url, controlled_did_percent_encoded
                )
                .as_str(),
            )
            .send()
            .await
            .expect("pass");
        assert_eq!(response.status(), 200);
        let response_body = response.text().await.expect("pass");
        // Verify that the response body is the expected DID document.
        assert_eq!(response_body, did_doc_record.did_document_jcs);
    }

    // Do a cycle of update_did and resolve via URD.
    for _ in 0..5 {
        let controlled_did = software_wallet
            .update_did(did, None, None)
            .await
            .expect("pass");
        {
            // Get the latest DID document -- this is the expected value.
            use did_webplus_wallet_store::WalletStorage;
            let did_doc_record = wallet_storage_a
                .as_did_doc_storage()
                .get_latest_known_did_doc_record(None, controlled_did.did())
                .await
                .expect("pass")
                .expect("pass");

            // Resolve the DID via the URD.
            let controlled_did_percent_encoded = percent_encode_did_query(&did);
            let response = test_util::REQWEST_CLIENT
                .get(
                    format!(
                        "{}/1.0/identifiers/{}",
                        urd_url, controlled_did_percent_encoded
                    )
                    .as_str(),
                )
                .send()
                .await
                .expect("pass");
            assert_eq!(response.status(), 200);
            let response_body = response.text().await.expect("pass");
            // Verify that the response body is the expected DID document.
            assert_eq!(response_body, did_doc_record.did_document_jcs);
        }
    }

    //
    // Tests are done, so shut down.
    //

    tracing::info!("Shutting down URD");
    urd_handle.abort();

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}

fn percent_encode_did_query(did_query: &str) -> String {
    const CONTROL_CHARS: percent_encoding::AsciiSet = percent_encoding::CONTROLS
        .add(b'%')
        .add(b'?')
        .add(b'=')
        .add(b'&');
    percent_encoding::percent_encode(did_query.as_bytes(), &CONTROL_CHARS).to_string()
}
