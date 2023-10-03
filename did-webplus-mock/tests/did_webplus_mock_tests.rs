use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus::{
    DIDDocument, DIDDocumentCreateParams, DIDDocumentUpdateParams, KeyPurpose,
    MicroledgerMutViewTrait, MicroledgerViewTrait, PublicKeySet,
};
use did_webplus_mock::{Microledger, MockResolver, MockVDR, MockVerifiedCache, MockWallet, JWS};
use selfhash::HashFunction;

fn priv_jwk_from_ed25519_signing_key(
    ed25519_signing_key: &ed25519_dalek::SigningKey,
) -> ssi_jwk::JWK {
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();
    ssi_jwk::JWK::from(ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
        curve: "Ed25519".to_string(),
        public_key: ssi_jwk::Base64urlUInt(ed25519_verifying_key.to_bytes().to_vec()),
        private_key: Some(ssi_jwk::Base64urlUInt(
            ed25519_signing_key.to_bytes().to_vec(),
        )),
    }))
}

// NOTE: This test is a rather low-level test of Microledger.  It's more complex than the one that uses MockWallet,
// but it's probably still useful to do these lower-level tests.
#[test]
#[serial_test::serial]
fn test_example_creating_and_updating_a_did() {
    println!("# Example: Creating and Updating a DID\n\nThis example can be run via command:\n\n    cargo test --all-features -- --nocapture test_example_creating_and_updating_a_did\n\n## Creating a DID\n");

    let signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_0 = signing_key_0.verifying_key();

    // Create a DID and its associated Microledger
    let (mut microledger, mut priv_jwk_0) = {
        let mut priv_jwk_0 = priv_jwk_from_ed25519_signing_key(&signing_key_0);
        println!(
            "For now, let's generate a single Ed25519 key to use in all the verification methods for the DID we will create.  In JWK format, the private key is:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_0).expect("pass")
        );
        let microledger = Microledger::create(
            DIDDocument::create_root(
                DIDDocumentCreateParams {
                    vdr_host: "example.com".into(),
                    valid_from: time::OffsetDateTime::now_utc(),
                    public_key_set: PublicKeySet {
                        authentication_v: vec![&verifying_key_0],
                        assertion_method_v: vec![&verifying_key_0],
                        key_agreement_v: vec![&verifying_key_0],
                        // Note that this is the one being used to self-sign the root DIDDocument.
                        capability_invocation_v: vec![&verifying_key_0],
                        capability_delegation_v: vec![&verifying_key_0],
                    },
                },
                &selfhash::Blake3,
                &signing_key_0,
            )
            .expect("pass"),
        )
        .expect("pass");
        let did = microledger.view().did().clone();
        use selfsign::Verifier;
        let latest_did_document = microledger.view().latest_did_document();
        println!("Creating a DID produces the root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):\n\n```json\n{}\n```\n\nNote that the `selfSignatureVerifier` field is a public key that is also found in the `capabilityInvocation` field.  This is the initial proof of control over the DID.\n", latest_did_document.to_json_pretty());
        println!("The associated DID document metadata (at the time of DID creation) is:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(&latest_did_document)).expect("pass"));
        // Add query params to bind this JWK to the latest DID doc.
        // Add (key ID) fragment to identify which key it is.
        let did_with_query_and_key_id_fragment = did
            .with_query(format!(
                "versionId={}&selfHash={}",
                latest_did_document.version_id(),
                latest_did_document.self_hash()
            ))
            .with_fragment(verifying_key_0.to_keri_verifier().into_owned());
        priv_jwk_0.key_id = Some(did_with_query_and_key_id_fragment.to_string());
        println!("We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_0).expect("pass"));
        (microledger, priv_jwk_0)
    };

    let signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_1 = signing_key_1.verifying_key();
    println!("## Updating the DID\n");
    // Update the Microledger.
    let mut priv_jwk_1 = {
        let mut priv_jwk_1 = priv_jwk_from_ed25519_signing_key(&signing_key_1);
        println!(
            "Let's generate another key to rotate in for some verification methods.  In JWK format, the new private key is:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_1).expect("pass")
        );
        let did_document_update_params = DIDDocumentUpdateParams {
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&verifying_key_0, &verifying_key_1],
                assertion_method_v: vec![&verifying_key_0],
                key_agreement_v: vec![&verifying_key_0],
                capability_invocation_v: vec![&verifying_key_1],
                capability_delegation_v: vec![&verifying_key_0],
            },
        };
        let non_root_did_document = DIDDocument::update_from_previous(
            microledger.view().latest_did_document(),
            did_document_update_params,
            selfhash::Blake3.new_hasher(),
            &signing_key_0,
        )
        .expect("pass");
        microledger
            .mut_view()
            .update(non_root_did_document)
            .expect("pass");
        let did = microledger.view().did().clone();
        use selfsign::Verifier;
        let latest_did_document = microledger.view().latest_did_document();
        println!("Updating a DID produces the next DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):\n\n```json\n{}\n```\n\nNote that the `selfSignatureVerifier` field is present in the previous (root) DID document's `capabilityInvocation` field.  This proves that the DID document was updated by an authorized entity.\n", latest_did_document.to_json_pretty());
        println!("The associated DID document metadata (at the time of DID update) is:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(&latest_did_document)).expect("pass"));
        println!("However, the DID document metadata associated with the root DID document has now become:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(microledger.view().root_did_document())).expect("pass"));
        let did_with_query_and_key_id_fragment = did
            .with_query(format!(
                "versionId={}&selfHash={}",
                latest_did_document.version_id(),
                latest_did_document.self_hash()
            ))
            .with_fragment(verifying_key_1.to_keri_verifier().into_owned());
        priv_jwk_1.key_id = Some(did_with_query_and_key_id_fragment.to_string());
        println!(
            "We set the new private JWK's `kid` field as earlier:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_1).expect("pass")
        );
        let did_with_query_and_key_id_fragment = did
            .with_query(format!(
                "versionId={}&selfHash={}",
                latest_did_document.version_id(),
                latest_did_document.self_hash()
            ))
            .with_fragment(verifying_key_0.to_keri_verifier().into_owned());
        priv_jwk_0.key_id = Some(did_with_query_and_key_id_fragment.to_string());
        println!("And update the first private JWK's `kid` field to point to the current DID document:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_0).expect("pass"));
        priv_jwk_1
    };

    let signing_key_2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_2 = signing_key_2.verifying_key();

    println!("## Updating the DID Again\n");
    // Update the Microledger.
    let _priv_jwk_2 = {
        let mut priv_jwk_2 = priv_jwk_from_ed25519_signing_key(&signing_key_2);
        println!(
            "Let's generate a third key to rotate in for some verification methods.  In JWK format, the new private key is:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_2).expect("pass")
        );
        let did_document_update_params = DIDDocumentUpdateParams {
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&verifying_key_0, &verifying_key_1],
                assertion_method_v: vec![&verifying_key_2],
                key_agreement_v: vec![&verifying_key_2],
                capability_invocation_v: vec![&verifying_key_2],
                capability_delegation_v: vec![&verifying_key_0],
            },
        };
        let non_root_did_document = DIDDocument::update_from_previous(
            microledger.view().latest_did_document(),
            did_document_update_params,
            selfhash::Blake3.new_hasher(),
            &signing_key_1,
        )
        .expect("pass");
        microledger
            .mut_view()
            .update(non_root_did_document)
            .expect("pass");
        let did = microledger.view().did().clone();
        use selfsign::Verifier;
        let latest_did_document = microledger.view().latest_did_document();
        println!("Updated DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):\n\n```json\n{}\n```\n\nNote that the `selfSignatureVerifier` field is present in the previous (root) DID document's `capabilityInvocation` field.  This proves that the DID document was updated by an authorized entity.\n", latest_did_document.to_json_pretty());
        println!("The associated DID document metadata (at the time of DID update) is:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(&latest_did_document)).expect("pass"));
        println!("Similarly, the DID document metadata associated with the previous DID document has now become:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(microledger.view().did_document_for_version_id(1).expect("pass"))).expect("pass"));
        println!("However, the DID document metadata associated with the root DID document has now become:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&microledger.view().did_document_metadata_for(microledger.view().root_did_document())).expect("pass"));
        let did_with_query_and_key_id_fragment = did
            .with_query(format!(
                "versionId={}&selfHash={}",
                latest_did_document.version_id(),
                latest_did_document.self_hash()
            ))
            .with_fragment(verifying_key_2.to_keri_verifier().into_owned());
        priv_jwk_2.key_id = Some(did_with_query_and_key_id_fragment.to_string());
        println!(
            "We set the new private JWK's `kid` field as earlier:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_2).expect("pass")
        );
        let did_with_query_and_key_id_fragment = did
            .with_query(format!(
                "versionId={}&selfHash={}",
                latest_did_document.version_id(),
                latest_did_document.self_hash()
            ))
            .with_fragment(verifying_key_0.to_keri_verifier().into_owned());
        priv_jwk_0.key_id = Some(did_with_query_and_key_id_fragment.to_string());
        println!("And update the first private JWK's `kid` field to point to the current DID document:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_0).expect("pass"));
        let did_with_query_and_key_id_fragment = did
            .with_query(format!(
                "versionId={}&selfHash={}",
                latest_did_document.version_id(),
                latest_did_document.self_hash()
            ))
            .with_fragment(verifying_key_1.to_keri_verifier().into_owned());
        priv_jwk_1.key_id = Some(did_with_query_and_key_id_fragment.to_string());
        println!("And update the first private JWK's `kid` field to point to the current DID document:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_1).expect("pass"));
        priv_jwk_2
    };
}

#[test]
#[serial_test::serial]
fn test_did_operations() {
    let mock_vdr_la = Arc::new(RwLock::new(MockVDR::new_with_host(
        "example.com".into(),
        None,
    )));
    let mock_vdr_lam = {
        let mut mock_vdr_lam = HashMap::new();
        mock_vdr_lam.insert("example.com".to_string(), mock_vdr_la.clone());
        mock_vdr_lam
    };
    let mut mock_verified_cache = MockVerifiedCache::empty("MockVerifiedCache".to_string());
    println!("----------------------------------------------------");
    println!("-- Wallet creation ---------------------------------");
    println!("----------------------------------------------------");
    let mut mock_wallet =
        MockWallet::new_with_vdr("Alice's Wallet".to_string(), mock_vdr_la.clone()).expect("pass");

    let mut mock_resolver =
        MockResolver::new("Bob's MockResolver".to_string(), mock_vdr_lam.clone());

    // Sign and verify a JWS.
    {
        let message = "This Alice is the best Alice.";
        // let jws = mock_wallet
        //     .sign_jws(
        //         mock_wallet
        //             .current_public_key_set
        //             .authentication_v
        //             .first()
        //             .expect("pass")
        //             .clone(),
        //         message.as_bytes(),
        //     )
        //     .expect("pass");
        // println!("jws: {}", jws);
        let signer = mock_wallet.signer_for_key_purpose(KeyPurpose::Authentication);
        let public_key = signer.verifier().to_keri_verifier().into_owned();
        // TODO: Better way to determine the kid field.
        use did_webplus::MicroledgerViewTrait;
        let kid = mock_wallet
            .did()
            .with_query(format!(
                "versionId={}&selfHash={}",
                mock_wallet
                    .microledger_view()
                    .latest_did_document()
                    .version_id(),
                mock_wallet
                    .microledger_view()
                    .latest_did_document()
                    .self_hash()
            ))
            .with_fragment(public_key.clone());
        let jws_string = JWS::signed(kid, message.as_bytes(), signer)
            .expect("pass")
            .encoded_to_string();
        println!("jws_string: {}", jws_string);

        // TODO: verify_jws (need a DID resolver).
        let decoded_jws = JWS::decoded_from_str(jws_string.as_str()).expect("pass");
        println!("decoded_jws: {:?}", decoded_jws);
        let did_document_validity_time_range = decoded_jws
            .verify(did_webplus::KeyPurpose::Authentication, &mut mock_resolver)
            .expect("pass");
        println!(
            "did_document_validity_time_range: {:?}",
            did_document_validity_time_range
        );
    }

    // Do some resolutions.
    println!("-- Let's do some DID resolutions ---------------------------------");
    {
        let (did_document, did_document_metadata) = mock_verified_cache
            .resolve(mock_wallet.did(), None, None, &mock_vdr_lam)
            .expect("pass");
        // This clone is necessary here to release the mutable borrow of mock_verified_cache.
        let did_document = did_document.clone();
        println!(
            "LATEST (which is root) did_document: {}",
            did_document.to_json_pretty()
        );
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        // Do a resolution against specific query params
        if false {
            {
                let (did_document_query, did_document_metadata_query) = mock_verified_cache
                    .resolve(mock_wallet.did(), Some(0), None, &mock_vdr_lam)
                    .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) = mock_verified_cache
                    .resolve(
                        mock_wallet.did(),
                        None,
                        Some(did_document.self_hash()),
                        &mock_vdr_lam,
                    )
                    .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) =
            // Both query params
            mock_verified_cache
                .resolve(mock_wallet.did(), Some(0), Some(did_document.self_hash()), &mock_vdr_lam)
                .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
        }
    }

    println!("----------------------------------------------------");
    println!("-- Wallet updates its DID (first update) -----------");
    println!("----------------------------------------------------");
    mock_wallet.update().expect("pass");

    // Do some resolutions.
    println!("-- Let's do some more resolutions ---------------------------------");
    {
        println!("-- First, we'll resolve the root DID document -----------------");
        let (did_document, did_document_metadata) = mock_verified_cache
            .resolve(mock_wallet.did(), Some(0), None, &mock_vdr_lam)
            .expect("pass");
        println!("ROOT did_document: {}", did_document.to_json_pretty());
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        println!("-- Now, we'll resolve the latest DID document -----------------");
        let (did_document, did_document_metadata) = mock_verified_cache
            .resolve(mock_wallet.did(), None, None, &mock_vdr_lam)
            .expect("pass");
        println!("LATEST did_document: {}", did_document.to_json_pretty());
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        println!("-- Finally, we'll resolve the latest DID document again -------");
        let (did_document, did_document_metadata) = mock_verified_cache
            .resolve(mock_wallet.did(), None, None, &mock_vdr_lam)
            .expect("pass");
        // This clone is necessary here to release the mutable borrow of mock_verified_cache.
        let did_document = did_document.clone();
        println!("LATEST did_document: {}", did_document.to_json_pretty());
        println!(
            "and its did_document_metadata: {}",
            serde_json::to_string_pretty(&did_document_metadata).expect("pass")
        );

        // Do a resolution against specific query params
        if false {
            {
                let (did_document_query, did_document_metadata_query) = mock_verified_cache
                    .resolve(
                        mock_wallet.did(),
                        Some(did_document.version_id()),
                        None,
                        &mock_vdr_lam,
                    )
                    .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) = mock_verified_cache
                    .resolve(
                        mock_wallet.did(),
                        None,
                        Some(did_document.self_hash()),
                        &mock_vdr_lam,
                    )
                    .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
            {
                let (did_document_query, did_document_metadata_query) =
            // Both query params
            mock_verified_cache
                .resolve(mock_wallet.did(), Some(did_document.version_id()), Some(did_document.self_hash()), &mock_vdr_lam)
                .expect("pass");
                assert_eq!(*did_document_query, did_document);
                assert_eq!(did_document_metadata_query, did_document_metadata);
            }
        }
    }
}
