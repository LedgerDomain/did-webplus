use std::{
    collections::HashMap,
    ops::Deref,
    sync::{Arc, RwLock},
};

use did_webplus_mock::{MockVDR, MockVDRClient, MockWallet};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    // TODO: Make env var to control full/compact/pretty/json formatting of logs
    tracing_subscriber::fmt()
        .with_target(true)
        .with_line_number(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();
}

async fn test_wallet_operations_impl(use_path: bool) {
    // Setup of mock services
    let mock_vdr_la = Arc::new(RwLock::new(MockVDR::new_with_host(
        "fancy.net".into(),
        None,
    )));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert("fancy.net".to_string(), mock_vdr_la.clone());
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
        .create_did("fancy.net".to_string(), did_path_o)
        .expect("pass");
    let alice_did_url = if let Some(alice_did_path) = alice_did.path_o().as_ref() {
        format!(
            "http://localhost:8085/{}/{}/did.json",
            alice_did_path,
            alice_did.root_self_hash()
        )
    } else {
        format!(
            "http://localhost:8085/{}/did.json",
            alice_did.root_self_hash()
        )
    };
    // Hacky way to test the actual VDR, which is assumed be running in a separate process.
    // This uses the DID document it created with the mock VDR and sends it to the real VDR.
    {
        use did_webplus::MicroledgerView;
        let alice_did_document = alice_wallet
            .controlled_did(&alice_did)
            .expect("pass")
            .microledger()
            .view()
            .latest_did_document();
        println!(
            "Alice's latest DID document: {}",
            alice_did_document.serialize_canonically().expect("pass")
        );
        assert_eq!(
            reqwest::Client::new()
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
        reqwest::Client::new()
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
        // Hacky way to test the actual VDR, which is assumed be running in a separate process.
        // This uses the DID document it updated with the mock VDR and sends it to the real VDR.
        {
            use did_webplus::MicroledgerView;
            let alice_did_document = alice_wallet
                .controlled_did(&alice_did)
                .expect("pass")
                .microledger()
                .view()
                .latest_did_document();
            println!(
                "Alice's latest DID document: {}",
                alice_did_document.serialize_canonically().expect("pass")
            );
            assert_eq!(
                reqwest::Client::new()
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
            println!("alice_did_url: {}", alice_did_url);
            let alice_did_url_self_hash = alice_did
                .resolution_url_for_self_hash(alice_did_document.self_hash().deref(), "http")
                .replace("fancy.net", "localhost:8085");
            println!(
                "alice_did_url with query self-hash: {}",
                alice_did_url_self_hash
            );
            let alice_did_url_version_id = alice_did
                .resolution_url_for_version_id(alice_did_document.version_id(), "http")
                .replace("fancy.net", "localhost:8085");
            println!(
                "alice_did_url with query version_id: {}",
                alice_did_url_version_id
            );
            assert_eq!(
                reqwest::Client::new()
                    .get(&alice_did_url)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
            // Do some query-specific GETs
            assert_eq!(
                reqwest::Client::new()
                    .get(&alice_did_url_self_hash)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
            assert_eq!(
                reqwest::Client::new()
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

#[tokio::test]
async fn test_wallet_operations() {
    test_wallet_operations_impl(false).await;
    test_wallet_operations_impl(true).await;
}
