use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus_core::DIDDocument;
use did_webplus_mock::{MicroledgerView, MockVDR, MockVDRClient, MockWallet};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

fn test_cache_headers(headers: &reqwest::header::HeaderMap, did_document: &DIDDocument) {
    tracing::trace!("HTTP response headers: {:?}", headers);
    assert!(headers.contains_key("Cache-Control"));
    // assert!(headers.contains_key("Expires"));
    assert!(headers.contains_key("Last-Modified"));
    assert!(headers.contains_key("ETag"));
    // This is a custom header that the VDG adds, mostly for testing purposes.
    assert!(headers.contains_key("X-DID-Webplus-VDG-Cache-Hit"));

    let cache_control = headers.get("Cache-Control").unwrap().to_str().unwrap();
    assert_eq!(
        cache_control,
        format!("public, max-age=0, no-cache, no-transform")
    );
    assert_eq!(
        headers.get("ETag").unwrap().to_str().unwrap(),
        did_document.self_hash.as_str()
    );
}

async fn test_vdg_wallet_operations_impl(use_path: bool) {
    test_util::wait_until_service_is_up(
        "Dockerized VDR",
        "http://dockerized.vdr.local:8085/health",
    )
    .await;
    test_util::wait_until_service_is_up(
        "Dockerized VDG",
        "http://dockerized.vdg.local:8086/health",
    )
    .await;

    let http_scheme_override = did_webplus_core::HTTPSchemeOverride::new()
        .with_override("dockerized.vdg.local".to_string(), "http")
        .expect("pass")
        .with_override("dockerized.vdr.local".to_string(), "http")
        .expect("pass");
    let http_scheme_override_o = Some(&http_scheme_override);

    // Setup of mock services
    let mock_vdr_la: Arc<RwLock<MockVDR>> = Arc::new(RwLock::new(MockVDR::new_with_hostname(
        "dockerized.vdr.local".into(),
        Some(8085),
        None,
    )));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert("dockerized.vdr.local".to_string(), mock_vdr_la.clone());
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
    for &base in &[
        // mbx::Base::Base58Btc,
        mbx::Base::Base64Url,
    ] {
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
            println!("Testing with mb_hash_function: {:?}", mb_hash_function);

            let alice_did = alice_wallet
                .create_did(
                    "dockerized.vdr.local".to_string(),
                    Some(8085),
                    did_path_o.clone(),
                    &mb_hash_function,
                )
                .expect("pass");

            let alice_did_documents_jsonl_url =
                alice_did.resolution_url_for_did_documents_jsonl(http_scheme_override_o);
            println!(
                "alice_did_documents_jsonl_url {}",
                alice_did_documents_jsonl_url
            );
            // Hacky way to test the actual VDR, which is assumed be running in a separate process.
            // This uses the DID document it created with the mock VDR and sends it to the real VDR.
            {
                let alice_did_document = alice_wallet
                    .controlled_did(&alice_did)
                    .expect("pass")
                    .microledger()
                    .view()
                    .latest_did_document();
                let alice_did_document_jcs =
                    alice_did_document.serialize_canonically().expect("pass");
                tracing::debug!("Alice's latest DID document: {}", alice_did_document_jcs);
                assert_eq!(
                    reqwest::Client::new()
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
                reqwest::Client::new()
                    .get(&alice_did_documents_jsonl_url)
                    .send()
                    .await
                    .expect("pass")
                    .status(),
                reqwest::StatusCode::OK
            );
            // Have it update the DID a bunch of times
            for _ in 0..5 {
                update_did(
                    &mut alice_wallet,
                    &alice_did,
                    &alice_did_documents_jsonl_url,
                )
                .await;
            }

            // sleep for a second to make sure the vdg gets updated
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Simplest test of the VDG for now.
            {
                let response: reqwest::Response = get_did_response(&alice_did.to_string()).await;
                assert_eq!(response.status(), reqwest::StatusCode::OK);
                let response_headers = response.headers().clone();
                let alice_did_document =
                    serde_json::from_str(response.text().await.expect("pass").as_str())
                        .expect("pass");
                test_cache_headers(&response_headers, &alice_did_document);
                assert!(
                    response_headers["X-DID-Webplus-VDG-Cache-Hit"]
                        .to_str()
                        .unwrap()
                        == "false"
                );
            }
            // Run it again to make sure the VDG has cached stuff.
            let response: reqwest::Response = get_did_response(&alice_did.to_string()).await;
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let response_headers = response.headers().clone();
            let alice_did_document =
                serde_json::from_str(response.text().await.expect("pass").as_str()).expect("pass");
            test_cache_headers(&response_headers, &alice_did_document);
            assert!(
                response_headers["X-DID-Webplus-VDG-Cache-Hit"]
                    .to_str()
                    .unwrap()
                    == "false"
            );

            // Ask for a particular version that the VDG is known to have to see if it hits the VDR.
            let alice_did_version_id_query = format!("{}?versionId=3", alice_did);
            let response: reqwest::Response = get_did_response(&alice_did_version_id_query).await;
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let response_headers = response.headers().clone();
            let alice_did_document =
                serde_json::from_str(response.text().await.expect("pass").as_str()).expect("pass");
            test_cache_headers(&response_headers, &alice_did_document);
            assert!(
                response_headers["X-DID-Webplus-VDG-Cache-Hit"]
                    .to_str()
                    .unwrap()
                    == "true",
                "response.headers: {:?}",
                response_headers
            );

            // Ask for a particular self-hash that the VDG is known to have to see if it hits the VDR.
            let alice_did_document = alice_wallet
                .controlled_did(&alice_did)
                .expect("pass")
                .microledger()
                .view()
                .latest_did_document();
            let alice_did_self_hash_query =
                format!("{}?selfHash={}", alice_did, alice_did_document.self_hash);
            let response = get_did_response(&alice_did_self_hash_query).await;
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert!(
                response.headers()["X-DID-Webplus-VDG-Cache-Hit"]
                    .to_str()
                    .unwrap()
                    == "true"
            );

            // Ask for both self-hash and version_id which are consistent.
            let alice_did_self_hash_version_query = format!(
                "{}?selfHash={}&versionId={}",
                alice_did, alice_did_document.self_hash, alice_did_document.version_id
            );
            let response = get_did_response(&alice_did_self_hash_version_query).await;
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert!(
                response.headers()["X-DID-Webplus-VDG-Cache-Hit"]
                    .to_str()
                    .unwrap()
                    == "true"
            );

            // Ask for both self-hash and version_id which are inconsistent.
            assert!(alice_did_document.version_id != 0);
            let alice_did_self_hash_version_inconsistent_query = format!(
                "{}?selfHash={}&versionId={}",
                alice_did, alice_did_document.self_hash, 0
            );
            let response = get_did_response(&alice_did_self_hash_version_inconsistent_query).await;
            assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);

            // Ask for a particular version that the VDG is known to have, but with a bad selfHash
            // to see if it will return an error.
            let alice_did_bad_query = format!("{}?versionId=3&selfHash=XXXX", alice_did);
            let response = get_did_response(&alice_did_bad_query).await;
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

            // Ask for a particular version that the VDG is known not to have to see if it errors correctly.
            let alice_did_version_id_query = format!("{}?versionId=6", alice_did);
            let response: reqwest::Response = get_did_response(&alice_did_version_id_query).await;
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

            // update the did again
            update_did(
                &mut alice_wallet,
                &alice_did,
                &alice_did_documents_jsonl_url,
            )
            .await;

            // sleep for a second to make sure the vdg gets updated
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Ask for the new version to see if the VDG has been notified of the update.
            let alice_did_version_id_query = format!("{}?versionId=6", alice_did);
            let response: reqwest::Response = get_did_response(&alice_did_version_id_query).await;
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(
                response.headers()["X-DID-Webplus-VDG-Cache-Hit"]
                    .to_str()
                    .unwrap(),
                "true"
            );
        }
    }
}

async fn update_did(
    alice_wallet: &mut MockWallet,
    alice_did: &did_webplus_core::DID,
    alice_did_documents_jsonl_url: &str,
) {
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
        let alice_did_document_jcs = alice_did_document.serialize_canonically().expect("pass");
        tracing::debug!("Alice's latest DID document: {}", alice_did_document_jcs);
        assert_eq!(
            reqwest::Client::new()
                .put(alice_did_documents_jsonl_url)
                .body(alice_did_document_jcs)
                .send()
                .await
                .expect("pass")
                .status(),
            reqwest::StatusCode::OK
        );
        // Fetch all DID documents for this DID again.
        assert_eq!(
            reqwest::Client::new()
                .get(alice_did_documents_jsonl_url)
                .send()
                .await
                .expect("pass")
                .status(),
            reqwest::StatusCode::OK
        );
    }
}

async fn get_did_response(did_query: &str) -> reqwest::Response {
    tracing::trace!(?did_query, "Getting DID response for VDG");
    let mut request_url = url::Url::parse("http://dockerized.vdg.local:8086").unwrap();
    request_url.path_segments_mut().unwrap().push("webplus");
    request_url.path_segments_mut().unwrap().push("v1");
    request_url.path_segments_mut().unwrap().push("resolve");
    // NOTE: `push` will percent-encode did_query!
    request_url.path_segments_mut().unwrap().push(did_query);
    tracing::trace!(?request_url, "DID query URL for VDG");
    reqwest::Client::new()
        .get(request_url.as_str())
        .send()
        .await
        .expect("pass")
}

// NOTE: This test is ignored because it requires that the dockerized VDG is running.
#[tokio::test]
#[ignore]
async fn test_vdg_wallet_operations() {
    test_vdg_wallet_operations_impl(false).await;
    test_vdg_wallet_operations_impl(true).await;
}
