use did_webplus_mock::{MicroledgerView, MockVDR, MockVDRClient, MockWallet};
use std::{
    collections::HashMap,
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
async fn test_vdr_wallet_operations_impl(
    vdr_hostname: &str,
    did_port_o: Option<u16>,
    use_path: bool,
) {
    let http_scheme_override = did_webplus_core::HTTPSchemeOverride::new()
        .with_override(vdr_hostname.to_string(), "http")
        .expect("pass");
    let http_scheme_override_o = Some(&http_scheme_override);

    // Setup of mock services
    let mock_vdr_la = Arc::new(RwLock::new(MockVDR::new_with_hostname(
        vdr_hostname.into(),
        did_port_o,
        None,
    )));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert(vdr_hostname.to_string(), mock_vdr_la.clone());
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
        .create_did(vdr_hostname.to_string(), did_port_o, did_path_o)
        .expect("pass");
    let alice_did_documents_jsonl_url =
        alice_did.resolution_url_for_did_documents_jsonl(http_scheme_override_o);
    tracing::trace!(
        "alice_did_documents_jsonl_url: {}",
        alice_did_documents_jsonl_url
    );

    // Hacky way to test the VDR without using a real Wallet.
    // This uses the DID document it created with the mock VDR and sends it to the real VDR.
    {
        let alice_did_document = alice_wallet
            .controlled_did(&alice_did)
            .expect("pass")
            .microledger()
            .view()
            .latest_did_document();
        let alice_did_document_jcs = alice_did_document.serialize_canonically().expect("pass");
        tracing::debug!(
            "Alice's latest DID document (HTTP POST-ing DID document to VDR): {}",
            alice_did_document_jcs
        );
        assert_eq!(
            test_util::REQWEST_CLIENT
                .post(&alice_did_documents_jsonl_url)
                .body(alice_did_document_jcs)
                .send()
                .await
                .expect("pass")
                .status(),
            reqwest::StatusCode::OK
        );
    }
    // Fetch all DID documents for this DID.
    assert_eq!(
        test_util::REQWEST_CLIENT
            .get(&alice_did_documents_jsonl_url)
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
            let alice_did_document = alice_wallet
                .controlled_did(&alice_did)
                .expect("pass")
                .microledger()
                .view()
                .latest_did_document();
            let alice_did_document_jcs = alice_did_document.serialize_canonically().expect("pass");
            tracing::debug!(
                "Alice's latest DID document (HTTP PUT-ing DID document to VDR): {}",
                alice_did_document_jcs
            );
            // Fetch all DID documents for this DID again.
            assert_eq!(
                test_util::REQWEST_CLIENT
                    .put(&alice_did_documents_jsonl_url)
                    .body(alice_did_document_jcs)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
        }
    }
}
