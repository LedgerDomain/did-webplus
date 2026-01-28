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

async fn test_vdr_wallet_operations_impl(use_path: bool) {
    test_util::wait_until_service_is_up("Dockerized VDR", "http://localhost:8085/health").await;

    let http_scheme_override = did_webplus_core::HTTPSchemeOverride::new()
        .with_override("dockerized.vdr.local".to_string(), "http")
        .expect("pass");
    let http_scheme_override_o = Some(&http_scheme_override);

    // Setup of mock services -- these are used locally to handle validation of DID documents, which will then
    // be sent to the real VDR.
    let mock_vdr_la = Arc::new(RwLock::new(MockVDR::new_with_hostname(
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
    // Create the wallet -- this MockWallet is used to create a DID document, which will then be sent to the real VDR.
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
                println!("Alice's latest DID document: {}", alice_did_document_jcs);
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
                // Hacky way to test the actual VDR, which is assumed be running in a separate process.
                // This uses the DID document it updated with the mock VDR and sends it to the real VDR.
                {
                    let alice_did_document = alice_wallet
                        .controlled_did(&alice_did)
                        .expect("pass")
                        .microledger()
                        .view()
                        .latest_did_document();
                    let alice_did_document_jcs =
                        alice_did_document.serialize_canonically().expect("pass");
                    println!("Alice's latest DID document: {}", alice_did_document_jcs);
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
                    assert_eq!(
                        test_util::REQWEST_CLIENT
                            .get(&alice_did_documents_jsonl_url)
                            .send()
                            .await
                            .expect("pass")
                            .status(),
                        reqwest::StatusCode::OK
                    );
                }
            }
        }
    }
}

// NOTE: This test is ignored because it requires that the dockerized VDR is running.
#[tokio::test]
#[ignore]
async fn test_vdr_wallet_operations() {
    test_vdr_wallet_operations_impl(false).await;
    test_vdr_wallet_operations_impl(true).await;
}
