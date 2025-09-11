use did_webplus_mock::{MockVDR, MockVDRClient, MockWallet};
use std::{
    collections::HashMap,
    ops::Deref,
    sync::{Arc, RwLock},
};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

// TODO: Maybe make separate sqlite and postgres versions of this test?
#[tokio::test]
async fn test_vdr_operations() {
    // Delete any existing database files so that we're starting from a consistent, blank start every time.
    // The postgres equivalent of this would be to "drop schema public cascade;" and "create schema public;"
    // TODO: postgres drop schema

    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        did_hostname: "localhost".to_string(),
        did_port_o: Some(9085),
        listen_port: 9085,
        // database_url: format!("sqlite://{}?mode=rwc", vdr_database_path),
        database_url: "postgres:///test_vdr_operations_vdr".to_string(),
        database_max_connections: 10,
        vdg_base_url_v: Vec::new(),
        http_scheme_override: Default::default(),
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");

    test_util::wait_until_service_is_up(
        "VDR",
        format!("http://localhost:{}/health", vdr_config.listen_port).as_str(),
    )
    .await;

    tracing::info!("Testing wallet operations; DID without path component");
    test_vdr_wallet_operations_impl(
        vdr_config.did_hostname.as_str(),
        vdr_config.did_port_o,
        false,
    )
    .await;

    tracing::info!("Testing wallet operations; DID with path component");
    test_vdr_wallet_operations_impl(
        vdr_config.did_hostname.as_str(),
        vdr_config.did_port_o,
        true,
    )
    .await;

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}

// NOTE: This is a very low-level test that doesn't require the wallet.  It would be much easier
// to do this from a Wallet.  Maybe get rid of this test in favor of a Wallet-driven test (though
// that would be testing two pieces of software at the same time).
async fn test_vdr_wallet_operations_impl(vdr_host: &str, did_port_o: Option<u16>, use_path: bool) {
    let http_scheme_override = did_webplus_core::HTTPSchemeOverride::new()
        .with_override(vdr_host.to_string(), "http")
        .expect("pass");
    let http_scheme_override_o = Some(&http_scheme_override);

    // Setup of mock services
    let mock_vdr_la = Arc::new(RwLock::new(MockVDR::new_with_host(
        vdr_host.into(),
        did_port_o,
        None,
    )));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert(vdr_host.to_string(), mock_vdr_la.clone());
        mock_vdr_lam
    };
    let mock_vdr_client_a = Arc::new(MockVDRClient::new(
        "Alice's MockVDRClient".to_string(),
        mock_vdr_lam.clone(),
    ));
    // Create the wallet.
    let mut alice_wallet = MockWallet::new("Alice's Wallet".to_string(), mock_vdr_client_a.clone());
    // Have it create a DID
    let did_path_o = if use_path {
        Some("user".to_string())
    } else {
        None
    };
    let alice_did = alice_wallet
        .create_did(vdr_host.to_string(), did_port_o, did_path_o)
        .expect("pass");
    let alice_did_url = alice_did.resolution_url(http_scheme_override_o);
    tracing::trace!("alice_did_url: {}", alice_did_url);

    // Hacky way to test the VDR without using a real Wallet.
    // This uses the DID document it created with the mock VDR and sends it to the real VDR.
    {
        use did_webplus_core::MicroledgerView;
        let alice_did_document = alice_wallet
            .controlled_did(&alice_did)
            .expect("pass")
            .microledger()
            .view()
            .latest_did_document();
        tracing::debug!(
            "Alice's latest DID document: {}",
            alice_did_document.serialize_canonically().expect("pass")
        );
        assert_eq!(
            test_util::REQWEST_CLIENT
                .post(&alice_did_url)
                // This is probably ok for now, because the self-sign-and-hash verification process will
                // re-canonicalize the document.  But it should still be re-canonicalized before being stored.
                .json(&alice_did_document)
                .send()
                .await
                .expect("pass")
                .status(),
            reqwest::StatusCode::OK
        );
    }
    // Resolve the DID
    assert_eq!(
        test_util::REQWEST_CLIENT
            .get(&alice_did_url)
            .send()
            .await
            .expect("pass")
            .status(),
        reqwest::StatusCode::OK
    );
    // Have it update the DID a bunch of times
    for _ in 0..5 {
        alice_wallet.update_did(&alice_did).expect("pass");
        // Hacky way to test the VDR without using a real Wallet.
        // This uses the DID document it updated with the mock VDR and sends it to the real VDR.
        {
            use did_webplus_core::MicroledgerView;
            let alice_did_document = alice_wallet
                .controlled_did(&alice_did)
                .expect("pass")
                .microledger()
                .view()
                .latest_did_document();
            tracing::debug!(
                "Alice's latest DID document: {}",
                alice_did_document.serialize_canonically().expect("pass")
            );
            assert_eq!(
                test_util::REQWEST_CLIENT
                    .put(&alice_did_url)
                    // This is probably ok for now, because the self-sign-and-hash verification process will
                    // re-canonicalize the document.  But it should still be re-canonicalized before being stored.
                    .json(&alice_did_document)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
            // Resolve the DID
            let alice_did_url_self_hash = alice_did.resolution_url_for_self_hash(
                alice_did_document.self_hash.deref(),
                http_scheme_override_o,
            );
            tracing::trace!(
                "alice_did_url with query self-hash: {}",
                alice_did_url_self_hash
            );
            let alice_did_url_version_id = alice_did.resolution_url_for_version_id(
                alice_did_document.version_id(),
                http_scheme_override_o,
            );
            tracing::trace!(
                "alice_did_url with query version_id: {}",
                alice_did_url_version_id
            );
            assert_eq!(
                test_util::REQWEST_CLIENT
                    .get(&alice_did_url)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
            // Do some query-specific GETs
            assert_eq!(
                test_util::REQWEST_CLIENT
                    .get(&alice_did_url_self_hash)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
            assert_eq!(
                test_util::REQWEST_CLIENT
                    .get(&alice_did_url_version_id)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
        }
    }
}
