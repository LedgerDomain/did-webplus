use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus_mock::{MockVDR, MockVDRClient, MockWallet};

#[tokio::test]
async fn test_wallet_operations() {
    // Setup of mock services
    let mock_vdr_la = Arc::new(RwLock::new(MockVDR::new_with_host(
        "example.com".into(),
        None,
    )));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert("example.com".to_string(), mock_vdr_la.clone());
        mock_vdr_lam
    };
    let mock_vdr_client_a = Arc::new(MockVDRClient::new(
        "Alice's MockVDRClient".to_string(),
        mock_vdr_lam.clone(),
    ));
    // Create the wallet.
    let mut alice_wallet = MockWallet::new("Alice's Wallet".to_string(), mock_vdr_client_a.clone());
    // Have it create a DID
    let alice_did = alice_wallet
        .create_did("example.com".to_string(), "user".to_string())
        .expect("pass");
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
            std::str::from_utf8(
                alice_did_document
                    .serialize_canonically_to_vec()
                    .expect("pass")
                    .as_slice()
            )
            .unwrap()
        );
        reqwest::Client::new()
            .post(format!("http://localhost:8085/{}", alice_did))
            // This is probably ok for now, because the self-sign-and-hash verification process will
            // re-canonicalize the document.  But it should still be re-canonicalized before being stored.
            .json(&alice_did_document)
            .send()
            .await
            .expect("pass");
    }
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
                std::str::from_utf8(
                    alice_did_document
                        .serialize_canonically_to_vec()
                        .expect("pass")
                        .as_slice()
                )
                .unwrap()
            );
            reqwest::Client::new()
                .put(format!("http://localhost:8085/{}", alice_did))
                // This is probably ok for now, because the self-sign-and-hash verification process will
                // re-canonicalize the document.  But it should still be re-canonicalized before being stored.
                .json(&alice_did_document)
                .send()
                .await
                .expect("pass");
        }
    }
}
