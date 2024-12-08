use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus_core::DIDDocument;
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
    tracing::trace!("HTTP response headers: {:?}", headers);
    assert!(headers.contains_key("Cache-Control"));
    assert!(headers.contains_key("Expires"));
    assert!(headers.contains_key("Last-Modified"));
    assert!(headers.contains_key("ETag"));
    // This is a custom header that the VDG adds, mostly for testing purposes.
    assert!(headers.contains_key("X-Cache-Hit"));

    let cache_control = headers.get("Cache-Control").unwrap().to_str().unwrap();
    let max_age = CACHE_DAYS * 24 * 60 * 60;
    assert_eq!(
        cache_control,
        format!("public, max-age={}, immutable", max_age)
    );
    assert_eq!(
        headers.get("ETag").unwrap().to_str().unwrap(),
        did_document.self_hash().as_str()
    );
}

// TODO: This won't work until ports are supported by the VDR (e.g. did:webplus:localhost%3A<port>:<self-hash>
// which resolves to http://localhost:<port>/<self-hash>/did.json)
#[tokio::test]
#[ignore]
async fn test_vdg_operations() {
    let vdg_config = did_webplus_vdg_lib::VDGConfig {
        service_domain: "localhost".to_string(),
        port: 10086,
        database_url: "postgres:///did_webplus_vdg".to_string(),
        database_max_connections: 10,
    };
    let vdg_handle = did_webplus_vdg_lib::spawn_vdg(vdg_config.clone())
        .await
        .expect("pass");
    let vdg_url = format!("http://{}:{}", vdg_config.service_domain, vdg_config.port);

    let vdr_config = did_webplus_vdr_lib::VDRConfig {
        service_domain: "localhost".to_string(),
        port: 10085,
        database_url: "postgres:///did_webplus_vdr".to_string(),
        database_max_connections: 10,
        gateways: vec![vdg_url.clone()],
    };
    let vdr_handle = did_webplus_vdr_lib::spawn_vdr(vdr_config.clone())
        .await
        .expect("pass");
    let vdr_url = format!("http://{}:{}", vdr_config.service_domain, vdr_config.port);

    tracing::info!("Testing wallet operations; DID without path component");
    test_wallet_operations_impl(vdr_url.as_str(), vdg_url.as_str(), false).await;

    tracing::info!("Testing wallet operations; DID with path component");
    test_wallet_operations_impl(vdr_url.as_str(), vdg_url.as_str(), true).await;

    tracing::info!("Shutting down VDG");
    vdg_handle.abort();

    tracing::info!("Shutting down VDR");
    vdr_handle.abort();
}

async fn test_wallet_operations_impl(vdr_url: &str, vdg_url: &str, use_path: bool) {
    const VDR_HOST: &str = "localhost";

    // Setup of mock services
    let mock_vdr_la: Arc<RwLock<MockVDR>> =
        Arc::new(RwLock::new(MockVDR::new_with_host(VDR_HOST.into(), None)));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert(VDR_HOST.to_string(), mock_vdr_la.clone());
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
        .create_did(VDR_HOST.to_string(), did_path_o)
        .expect("pass");
    let alice_did_url = if let Some(alice_did_path) = alice_did.path_o().as_ref() {
        format!(
            "{}/{}/{}/did.json",
            vdr_url,
            alice_did_path,
            alice_did.root_self_hash()
        )
    } else {
        format!("{}/{}/did.json", vdr_url, alice_did.root_self_hash())
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
        update_did(&mut alice_wallet, &alice_did, &alice_did_url).await;
    }

    // sleep for a second to make sure the vdg gets updated
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Simplest test of the VDG for now.
    {
        let response: reqwest::Response = get_did_response(vdg_url, alice_did.as_str()).await;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let response_headers = response.headers().clone();
        let alice_did_document =
            serde_json::from_str(response.text().await.expect("pass").as_str()).expect("pass");
        test_cache_headers(&response_headers, &alice_did_document);
        assert!(response_headers["X-Cache-Hit"].to_str().unwrap() == "false");
    }
    // Run it again to make sure the VDG has cached stuff.
    let response: reqwest::Response = get_did_response(vdg_url, alice_did.as_str()).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response_headers = response.headers().clone();
    let alice_did_document =
        serde_json::from_str(response.text().await.expect("pass").as_str()).expect("pass");
    test_cache_headers(&response_headers, &alice_did_document);
    assert!(response_headers["X-Cache-Hit"].to_str().unwrap() == "false");

    // Ask for a particular version that the VDG is known to have to see if it hits the VDR.
    let alice_did_version_id_query = format!("{}?versionId=3", alice_did);
    let response: reqwest::Response = get_did_response(vdg_url, &alice_did_version_id_query).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response_headers = response.headers().clone();
    let alice_did_document =
        serde_json::from_str(response.text().await.expect("pass").as_str()).expect("pass");
    test_cache_headers(&response_headers, &alice_did_document);
    assert!(
        response_headers["X-Cache-Hit"].to_str().unwrap() == "true",
        "response.headers: {:?}",
        response_headers
    );

    // Ask for a particular self-hash that the VDG is known to have to see if it hits the VDR.
    use did_webplus_core::MicroledgerView;
    let alice_did_document = alice_wallet
        .controlled_did(&alice_did)
        .expect("pass")
        .microledger()
        .view()
        .latest_did_document();
    let alice_did_self_hash_query =
        format!("{}?selfHash={}", alice_did, alice_did_document.self_hash());
    let response = get_did_response(vdg_url, &alice_did_self_hash_query).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(response.headers()["X-Cache-Hit"].to_str().unwrap() == "true");

    // Ask for both self-hash and version_id which are consistent.
    let alice_did_self_hash_version_query = format!(
        "{}?selfHash={}&versionId={}",
        alice_did,
        alice_did_document.self_hash(),
        alice_did_document.version_id
    );
    let response = get_did_response(vdg_url, &alice_did_self_hash_version_query).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(response.headers()["X-Cache-Hit"].to_str().unwrap() == "true");

    // Ask for both self-hash and version_id which are inconsistent.
    assert!(alice_did_document.version_id != 0);
    let alice_did_self_hash_version_inconsistent_query = format!(
        "{}?selfHash={}&versionId={}",
        alice_did,
        alice_did_document.self_hash(),
        0
    );
    let response = get_did_response(vdg_url, &alice_did_self_hash_version_inconsistent_query).await;
    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);

    // Ask for a particular version that the VDG is known to have, but with a bad selfHash
    // to see if it will return an error.
    let alice_did_bad_query = format!("{}?versionId=3&selfHash=XXXX", alice_did);
    let response = get_did_response(vdg_url, &alice_did_bad_query).await;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    // Ask for a particular version that the VDG is known not to have to see if it errors correctly.
    let alice_did_version_id_query = format!("{}?versionId=6", alice_did);
    let response: reqwest::Response = get_did_response(vdg_url, &alice_did_version_id_query).await;
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    // update the did again
    update_did(&mut alice_wallet, &alice_did, &alice_did_url).await;

    // sleep for a second to make sure the vdg gets updated
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Ask for the new version to see if the VDG has been notified of the update.
    let alice_did_version_id_query = format!("{}?versionId=6", alice_did);
    let response: reqwest::Response = get_did_response(vdg_url, &alice_did_version_id_query).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["X-Cache-Hit"].to_str().unwrap(), "true");
}

async fn update_did(
    alice_wallet: &mut MockWallet,
    alice_did: &did_webplus_core::DID,
    alice_did_url: &String,
) {
    use did_webplus_core::MicroledgerView;

    alice_wallet.update_did(alice_did).expect("pass");
    // Hacky way to test the actual VDR, which is assumed be running in a separate process.
    // This uses the DID document it updated with the mock VDR and sends it to the real VDR.
    {
        let alice_did_document = alice_wallet
            .controlled_did(alice_did)
            .expect("pass")
            .microledger()
            .view()
            .latest_did_document();
        tracing::debug!(
            "Alice's latest DID document: {}",
            alice_did_document.serialize_canonically().expect("pass")
        );
        assert_eq!(
            reqwest::Client::new()
                .put(alice_did_url)
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
                .get(alice_did_url)
                .send()
                .await
                .expect("pass")
                .status(),
            reqwest::StatusCode::OK
        );
    }
}

async fn get_did_response(vdg_url: &str, did_query: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!(
            "{}/{}",
            vdg_url,
            temp_hack_incomplete_url_encoded(did_query)
        ))
        .send()
        .await
        .expect("pass")
}

// #[tokio::test]
// async fn test_wallet_operations() {
//     test_wallet_operations_impl(false).await;
//     test_wallet_operations_impl(true).await;
// }

/// INCOMPLETE, TEMP HACK
fn temp_hack_incomplete_url_encoded(s: &str) -> String {
    s.replace('?', "%3F")
        .replace('=', "%3D")
        .replace('&', "%26")
}