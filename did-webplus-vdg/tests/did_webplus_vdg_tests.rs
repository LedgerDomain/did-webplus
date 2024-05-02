use std::{
    collections::HashMap,
    ops::Deref,
    sync::{Arc, RwLock},
};

use did_webplus::DIDDocument;
use did_webplus_mock::{MockVDR, MockVDRClient, MockWallet};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    // Ignore errors, since there may not be a .env file (e.g. in docker image)
    let _ = dotenvy::dotenv();

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    // TODO: Make env var to control full/compact/pretty/json formatting of logs
    tracing_subscriber::fmt()
        .with_target(true)
        .with_line_number(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();
}

const CACHE_DAYS: u64 = 365;

fn test_cache_headers(headers: &reqwest::header::HeaderMap, did_document: &DIDDocument) {
    assert!(headers.contains_key("Cache-Control"));
    assert!(headers.contains_key("Expires"));
    assert!(headers.contains_key("Last-Modified"));
    assert!(headers.contains_key("ETag"));

    let cache_control = headers.get("Cache-Control").unwrap().to_str().unwrap();
    let max_age = CACHE_DAYS * 24 * 60 * 60;
    assert_eq!(
        cache_control,
        format!("public, max-age={}, immutable", max_age)
    );
    assert_eq!(
        headers.get("ETag").unwrap().to_str().unwrap(),
        did_document.self_hash().deref()
    );
}

async fn test_wallet_operations_impl(use_path: bool) {
    // Setup of mock services
    let mock_vdr_la: Arc<RwLock<MockVDR>> = Arc::new(RwLock::new(MockVDR::new_with_host(
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
            alice_did.self_hash()
        )
    } else {
        format!("http://localhost:8085/{}/did.json", alice_did.self_hash())
    };
    // Hacky way to test the actual VDR, which is assumed be running in a separate process.
    // This uses the DID document it created with the mock VDR and sends it to the real VDR.
    {
        let alice_did_document = alice_wallet
            .controlled_did(&alice_did)
            .expect("pass")
            .microledger()
            .view()
            .latest_did_document();
        tracing::debug!(
            "Alice's latest DID document: {}",
            std::str::from_utf8(
                alice_did_document
                    .serialize_canonically_to_vec()
                    .expect("pass")
                    .as_slice()
            )
            .unwrap()
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
            let alice_did_document = alice_wallet
                .controlled_did(&alice_did)
                .expect("pass")
                .microledger()
                .view()
                .latest_did_document();
            tracing::debug!(
                "Alice's latest DID document: {}",
                std::str::from_utf8(
                    alice_did_document
                        .serialize_canonically_to_vec()
                        .expect("pass")
                        .as_slice()
                )
                .unwrap()
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
            assert_eq!(
                reqwest::Client::new()
                    .get(&alice_did_url)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
        }
    }

    // Simplest test of the VDG for now.
    {
        let response = reqwest::Client::new()
            .get(&format!("http://localhost:8086/{}", alice_did))
            .send()
            .await
            .expect("pass");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let response_headers = response.headers().clone();
        let alice_did_document =
            serde_json::from_str(response.text().await.expect("pass").as_str()).expect("pass");
        test_cache_headers(&response_headers, &alice_did_document);
    }
    // Run it again to make sure the VDG has cached stuff.
    assert_eq!(
        reqwest::Client::new()
            .get(&format!("http://localhost:8086/{}", alice_did))
            .send()
            .await
            .expect("pass")
            .status(),
        reqwest::StatusCode::OK
    );
    // Ask for a particular version that the VDG is known to have to see if it hits the VDR.
    let alice_did_version_id_query = format!("{}?versionId=3", alice_did);
    assert_eq!(
        reqwest::Client::new()
            .get(&format!(
                "http://localhost:8086/{}",
                url_encoded(&alice_did_version_id_query)
            ))
            .send()
            .await
            .expect("pass")
            .status(),
        reqwest::StatusCode::OK
    );
    // Ask for a particular self-hash that the VDG is known to have to see if it hits the VDR.
    use did_webplus::MicroledgerView;
    let alice_did_document = alice_wallet
        .controlled_did(&alice_did)
        .expect("pass")
        .microledger()
        .view()
        .latest_did_document();
    let alice_did_self_hash_query =
        format!("{}?selfHash={}", alice_did, alice_did_document.self_hash());
    assert_eq!(
        reqwest::Client::new()
            .get(&format!(
                "http://localhost:8086/{}",
                url_encoded(&alice_did_self_hash_query)
            ))
            .send()
            .await
            .expect("pass")
            .status(),
        reqwest::StatusCode::OK
    );
    // Ask for both self-hash and version_id which are consistent.
    let alice_did_self_hash_version_query = format!(
        "{}?selfHash={}&versionId={}",
        alice_did,
        alice_did_document.self_hash(),
        alice_did_document.version_id
    );
    assert_eq!(
        reqwest::Client::new()
            .get(&format!(
                "http://localhost:8086/{}",
                url_encoded(&alice_did_self_hash_version_query)
            ))
            .send()
            .await
            .expect("pass")
            .status(),
        reqwest::StatusCode::OK
    );
    // Ask for both self-hash and version_id which are inconsistent.
    assert!(alice_did_document.version_id != 0);
    let alice_did_self_hash_version_inconsistent_query = format!(
        "{}?selfHash={}&versionId={}",
        alice_did,
        alice_did_document.self_hash(),
        0
    );
    assert_eq!(
        reqwest::Client::new()
            .get(&format!(
                "http://localhost:8086/{}",
                url_encoded(&alice_did_self_hash_version_inconsistent_query)
            ))
            .send()
            .await
            .expect("pass")
            .status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY
    );
    // Ask for a particular version that the VDG is known to have, but with a bad selfHash
    // to see if it will return an error.
    let alice_did_bad_query = format!("{}?versionId=3&selfHash=XXXX", alice_did);
    assert_eq!(
        reqwest::Client::new()
            .get(&format!(
                "http://localhost:8086/{}",
                url_encoded(&alice_did_bad_query)
            ))
            .send()
            .await
            .expect("pass")
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn test_wallet_operations() {
    test_wallet_operations_impl(false).await;
    test_wallet_operations_impl(true).await;
}

/// INCOMPLETE, TEMP HACK
fn url_encoded(s: &str) -> String {
    s.replace('?', "%3F")
        .replace('=', "%3D")
        .replace('&', "%26")
}
