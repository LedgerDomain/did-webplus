use std::{ops::Deref, str::FromStr};

use did_webplus_core::{
    CreationMetadata, DIDDocument, DIDDocumentMetadata, DIDKeyResourceFullyQualified,
    HashedUpdateKey, LatestUpdateMetadata, NextUpdateMetadata, PublicKeySet, RootLevelUpdateRules,
    UpdateKey, UpdatesDisallowed, now_utc_milliseconds,
};

/// This will run once at load time (i.e. presumably before main function is called).
#[ctor::ctor]
fn overall_init() {
    test_util::ctor_overall_init();
}

#[test]
#[serial_test::serial]
fn test_roundtrip_did_basic() {
    let str_v = [
        "did:webplus:example.com:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "did:webplus:example.com:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "did:webplus:example.com:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "did:webplus:example.com%3A9999:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "did:webplus:example.com%3A9999:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "did:webplus:example.com%3A9999:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
    ];
    for s in str_v {
        let did = did_webplus_core::DID::from_str(s).expect("pass");
        println!("string form of DID: {}", s);
        println!("parsed DID: {:?}", did);
        let s2 = did.to_string();
        println!("re-stringed form of DID: {}", s);
        assert_eq!(s, &s2);
    }
}

#[test]
#[serial_test::serial]
fn test_roundtrip_did_with_query() {
    // Note that the String -> String roundtrip depends on the specific order of selfHash
    // then versionId in the query params.
    let str_v = [
        "did:webplus:example.com:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?versionId=3",
        "did:webplus:example.com:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?versionId=3",
        "did:webplus:example.com:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?versionId=3",
        "did:webplus:example.com:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw",
        "did:webplus:example.com:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw",
        "did:webplus:example.com:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw",
        "did:webplus:example.com:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3",
        "did:webplus:example.com:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3",
        "did:webplus:example.com:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3",
        "did:webplus:example.com%3A9999:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?versionId=3",
        "did:webplus:example.com%3A9999:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?versionId=3",
        "did:webplus:example.com%3A9999:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?versionId=3",
        "did:webplus:example.com%3A9999:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw",
        "did:webplus:example.com%3A9999:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw",
        "did:webplus:example.com%3A9999:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw",
        "did:webplus:example.com%3A9999:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3",
        "did:webplus:example.com%3A9999:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3",
        "did:webplus:example.com%3A9999:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3",
    ];
    for s in str_v {
        let did_with_query = did_webplus_core::DIDWithQueryStr::new_ref(s).expect("pass");
        println!("string form of DID with query: {}", s);
        println!("DIDWithQuery: {:?}", did_with_query);
        let s2 = did_with_query.to_string();
        println!("re-stringed form of DIDWithQuery: {}", s);
        assert_eq!(s, &s2);
    }
}

#[test]
#[serial_test::serial]
fn test_roundtrip_did_key_resource_fully_qualified() {
    let str_v = [
        "did:webplus:example.com:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3#0",
        "did:webplus:example.com:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3#0",
        "did:webplus:example.com:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3#0",
        "did:webplus:example.com%3A9999:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3#0",
        "did:webplus:example.com%3A9999:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3#0",
        "did:webplus:example.com%3A9999:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA?selfHash=uHiChTLrLvHHZDiWWLUJHHyW2Bk10vCp3Mh7sMEVVfHImDw&versionId=3#0",
    ];
    for s in str_v {
        let did = did_webplus_core::DIDKeyResourceFullyQualified::from_str(s).expect("pass");
        println!("string form of DID: {}", s);
        println!("parsed DID: {:?}", did);
        let s2 = did.to_string();
        println!("re-stringed form of DID: {}", s);
        assert_eq!(s, &s2);
    }
}

#[test]
#[serial_test::serial]
fn test_roundtrip_did_key_resource() {
    let str_v = [
        "did:webplus:example.com:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA#0",
        "did:webplus:example.com:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA#0",
        "did:webplus:example.com:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA#0",
        "did:webplus:example.com%3A9999:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA#0",
        "did:webplus:example.com%3A9999:user:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA#0",
        "did:webplus:example.com%3A9999:user:thingy:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA#0",
    ];
    for s in str_v {
        let did = did_webplus_core::DIDKeyResource::from_str(s).expect("pass");
        println!("string form of DID: {}", s);
        println!("parsed DID: {:?}", did);
        let s2 = did.to_string();
        println!("re-stringed form of DID: {}", s);
        assert_eq!(s, &s2);
    }
}

// TODO: How to enable this feature in dev-dependencies?
#[cfg(feature = "ed25519-dalek")]
#[test]
#[serial_test::serial]
fn test_root_did_document_sign_and_verify() {
    let update_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_verifying_key = update_signing_key.verifying_key();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let pub_key =
        mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key);

    // Determine the update rules; just the one key.
    let update_pub_key = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_verifying_key,
    );
    // Use HashedUpdateKey
    let update_rules = did_webplus_core::RootLevelUpdateRules::from(
        did_webplus_core::HashedUpdateKey::from_pub_key(&update_pub_key),
    );

    let did_hostname = "example.com";
    for did_port_o in [None, Some(3000)] {
        for did_path_o in [None, Some("user")] {
            // Create the root DID document.

            use did_webplus_core::now_utc_milliseconds;
            let mut root_did_document = DIDDocument::create_unsigned_root(
                did_hostname,
                did_port_o,
                did_path_o,
                update_rules.clone(),
                now_utc_milliseconds(),
                PublicKeySet {
                    authentication_v: vec![&pub_key],
                    assertion_method_v: vec![&pub_key],
                    key_agreement_v: vec![&pub_key],
                    capability_invocation_v: vec![&pub_key],
                    capability_delegation_v: vec![&pub_key],
                },
                &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
            )
            .expect("pass");

            // Sign the root DID document.
            let jws = root_did_document
                .sign(update_pub_key.to_string(), &update_signing_key)
                .expect("pass");

            println!("jws: {}", jws);
            println!("jws.header: {:?}", jws.header());

            // Add the proof to the DID document.
            root_did_document.add_proof(jws.into_string());

            // Finalize the root DID document.
            root_did_document.finalize(None).expect("pass");

            // Now verify the root DID document.
            root_did_document.verify_root_nonrecursive().expect("pass");

            println!(
                "root did_document:\n{}",
                serde_json::to_string_pretty(&root_did_document).unwrap()
            );
        }
    }
}

#[cfg(feature = "ed25519-dalek")]
#[test]
#[serial_test::serial]
fn test_did_update_sign_and_verify() {
    use did_webplus_core::now_utc_milliseconds;

    println!(
        "# Example: DID Microledger\n\nThis example can be run via command:\n\n    cargo test -p did-webplus-core --all-features -- --nocapture test_did_update_sign_and_verify\n\n## Example DID Documents\n\nHere is an example of the DID documents in the microledger for a DID.\n\nRoot DID document (`versionId` 0):\n"
    );

    let update_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_verifying_key_0 = update_signing_key_0.verifying_key();
    // Determine the update rules; just the one key, and just use did:key to identify it.
    let update_pub_key_0 = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_verifying_key_0,
    );
    // Use HashedUpdateKey
    let update_rules = did_webplus_core::RootLevelUpdateRules::from(
        did_webplus_core::HashedUpdateKey::from_pub_key(&update_pub_key_0),
    );

    // Create the keypair for the verification method.
    let signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_0 = signing_key_0.verifying_key();
    let pub_key_0 =
        mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_0);

    // Create the root DID document.
    let mut root_did_document = DIDDocument::create_unsigned_root(
        "example.com",
        None,
        None,
        update_rules,
        now_utc_milliseconds(),
        PublicKeySet {
            authentication_v: vec![&pub_key_0],
            assertion_method_v: vec![&pub_key_0],
            key_agreement_v: vec![&pub_key_0],
            capability_invocation_v: vec![&pub_key_0],
            capability_delegation_v: vec![&pub_key_0],
        },
        &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
    )
    .expect("pass");

    // Finalize the root DID document.
    root_did_document.finalize(None).expect("pass");

    // Now verify the root DID document.
    root_did_document.verify_root_nonrecursive().expect("pass");

    println!(
        "```json\n{}\n```\n\nNote that the `proofs` field is omitted since no proofs are required for the root DID document.  However, they MAY be present.\n\nNext DID Document (`versionId` 1), in particular having new `updateRules`:\n",
        serde_json::to_string_pretty(&root_did_document).unwrap()
    );

    // Now create a second DID document, which is a non-root DID document.  Create another key to be rotated in,
    // and create another update rules key.

    // Determine the update rules; just the one key, and just use did:key to identify it.
    let update_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_verifying_key_1 = update_signing_key_1.verifying_key();
    let update_pub_key_1 = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_verifying_key_1,
    );
    // This time, just use UpdateKey, instead of HashedUpdateKey.
    let update_rules = did_webplus_core::RootLevelUpdateRules::from(did_webplus_core::UpdateKey {
        pub_key: update_pub_key_1.clone(),
    });

    // Create the new keypair for the verification method.
    let signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_1 = signing_key_1.verifying_key();
    let pub_key_1 =
        mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_1);

    let mut did_document_1 = DIDDocument::create_unsigned_non_root(
        &root_did_document,
        update_rules,
        now_utc_milliseconds(),
        PublicKeySet {
            authentication_v: vec![&pub_key_1],
            assertion_method_v: vec![&pub_key_0],
            key_agreement_v: vec![&pub_key_0],
            capability_invocation_v: vec![&pub_key_1],
            capability_delegation_v: vec![&pub_key_0],
        },
        &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
    )
    .expect("pass");

    // Sign the DID document.
    let jws = did_document_1
        .sign(update_pub_key_0.to_string(), &update_signing_key_0)
        .expect("pass");

    // Add the proof to the DID document.
    did_document_1.add_proof(jws.to_string());

    // Finalize the DID document.
    did_document_1
        .finalize(Some(&root_did_document))
        .expect("pass");

    // Now verify the DID document.
    did_document_1
        .verify_non_root_nonrecursive(&root_did_document)
        .expect("pass");

    println!(
        "```json\n{}\n```\n",
        serde_json::to_string_pretty(&did_document_1).unwrap()
    );

    {
        println!(
            "Note that the element in the `proofs` field is a JWS whose header decodes as:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(jws.header()).unwrap()
        );
    }
    {
        use selfhash::HashFunctionT;
        let mut hasher = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url).new_hasher();
        use selfhash::HasherT;
        hasher.update(update_pub_key_0.as_bytes());
        let hashed_pub_key = hasher.finalize();
        println!(
            "Note that the hash of the `kid` field of the JWS header is `{}` which should match the `hashedKey` field of the previous DID Document's `updateRules`.\n",
            hashed_pub_key
        );
    }

    // Make one more update, but this time use UpdatesDisallowed, and publish no verification methods.
    // This effectively deactivates the DID.
    let update_rules =
        did_webplus_core::RootLevelUpdateRules::from(did_webplus_core::UpdatesDisallowed {});
    let mut did_document_2 = DIDDocument::create_unsigned_non_root(
        &did_document_1,
        update_rules,
        now_utc_milliseconds(),
        PublicKeySet {
            authentication_v: vec![],
            assertion_method_v: vec![],
            key_agreement_v: vec![],
            capability_invocation_v: vec![],
            capability_delegation_v: vec![],
        },
        &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
    )
    .expect("pass");

    // Sign the DID document.
    let jws = did_document_2
        .sign(update_pub_key_1.to_string(), &update_signing_key_1)
        .expect("pass");

    // Add the proof to the DID document.
    did_document_2.add_proof(jws.to_string());

    // Finalize the DID document.
    did_document_2
        .finalize(Some(&did_document_1))
        .expect("pass");

    // Now verify the DID document.
    did_document_2
        .verify_non_root_nonrecursive(&did_document_1)
        .expect("pass");

    println!(
        "Next DID Document (`versionId` 2), which shows how to deactivate a DID by setting `updateRules` to `{{}}`:\n\n```json\n{}\n```\n\nRemoving all verification methods from a deactivated DID is RECOMMENDED so that no unrevocable keys are left in the DID document, but is not required.  Note that the element in the `proofs` field is a JWS whose header decodes as:\n\n```json\n{}\n```\n\nNote that the `kid` field of the JWS header matches the `key` field of the previous DID Document's `updateRules`.\n",
        serde_json::to_string_pretty(&did_document_2).unwrap(),
        serde_json::to_string_pretty(jws.header()).unwrap()
    );
}

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

#[test]
#[serial_test::serial]
fn test_signature_generation_with_witness() {
    let signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_0 = signing_key_0.verifying_key();
    let pub_key_0 =
        mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_0);
    let mut priv_jwk_0 = priv_jwk_from_ed25519_signing_key(&signing_key_0);

    println!(
        "# Example: Signature Generation With Witness\n\nThis example can be run via command:\n\n    cargo test -p did-webplus-core --all-features -- --nocapture test_signature_generation_with_witness\n\nBy specifying the `versionId` and `selfHash` query params in the `kid` field of a signature (header), the signer is committing to a specific DID document version having a specific `selfHash` value.  This acts as a witness in a limited way, making forking a DID microledger much more difficult.  Note that use of a Verifiable Data Gateway (described elsewhere) is the recommended way for preventing signature repudiation and forking of DIDs.\n"
    );

    // TODO: Other key types
    {
        println!(
            "## Key Generation and DID Creation\n\nWe generate a private key and create a DID using the public key for the verification methods.  The generated private key is:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_0).expect("pass")
        );

        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: pub_key_0.clone(),
        });
        let now_utc = now_utc_milliseconds();
        let mut did_document_0 = DIDDocument::create_unsigned_root(
            "example.com",
            None,
            None,
            update_rules,
            now_utc,
            PublicKeySet {
                authentication_v: vec![&pub_key_0],
                assertion_method_v: vec![&pub_key_0],
                key_agreement_v: vec![&pub_key_0],
                capability_invocation_v: vec![&pub_key_0],
                capability_delegation_v: vec![&pub_key_0],
            },
            &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
        )
        .expect("pass");

        // No need to sign the root DID document, but it is allowed.

        // Finalize the root DID document.  This will self-hash the DID document.
        did_document_0.finalize(None).expect("pass");

        did_document_0.verify_root_nonrecursive().expect("pass");

        let did = did_document_0.did.clone();
        println!(
            "Root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&did_document_0).unwrap()
        );
        // Add query params for versionId and selfHash, so that the signature produced with this key commits
        // the DID document with the given versionId to have the given selfHash.  This manifests a limited
        // form of witnessing.
        let did_key_resource_fully_qualified: DIDKeyResourceFullyQualified = did
            .with_queries(&did_document_0.self_hash, did_document_0.version_id)
            // NOTE: This is hardcoded, and depends on the order the keys were added to the DID document.
            .with_fragment("0");
        // Set the key_id field of the JWK, so that it appears in the header of JWS signatures.
        priv_jwk_0.key_id = Some(did_key_resource_fully_qualified.to_string());
        println!(
            "We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&priv_jwk_0).expect("pass")
        );

        // Sign stuff.
        let payload = "{\"HIPPOS\":\"much better than OSTRICHES\"}";
        println!(
            "## Signature Generation\n\nWe'll sign a JSON payload and produce a JWS.  The payload is:\n\n```json\n{}\n```\n",
            payload
        );
        let jws = ssi_jws::encode_sign(
            priv_jwk_0.get_algorithm().expect("pass"),
            payload,
            &priv_jwk_0,
        )
        .expect("pass");
        println!("The resulting JWS is:\n\n    {}\n", jws);
        // Verify signature.
        let pub_jwk_0 = priv_jwk_0.to_public();
        let (jws_header, decoded_payload) = ssi_jws::decode_verify(&jws, &pub_jwk_0).expect("pass");
        assert_eq!(decoded_payload.as_slice(), payload.as_bytes());
        println!(
            "Decoding the JWS, the header is:\n\n```json\n{}\n```\n\nWhen this JWS is verified by another party, they will resolve the DID document and key specified by the `kid` field.  This DID document resolution involves verifying the DID microledger up through the specified DID document (in real applications, this will be handled by a Verifiable Data Gateway which retrieves and verifies DID microledgers ahead of time).  Once the DID microledger is verified, the JWS can be verified against the public key listed in the DID document.  The DID resolution will also produce the DID document metadata, which indicates if the resolved DID document is the current DID document or not.  Depending on the particular use case, the currency of the signing key may or may not be relevant.",
            serde_json::to_string_pretty(&jws_header).unwrap()
        );

        // Ensure this splitting, re-forming, and verifying the JWS actually works, so that the test
        // of the altered JWS payload is actually meaningful.
        {
            let (jws_header, jws_payload, jws_signature) = ssi_jws::split_jws(&jws).expect("pass");
            let reformed_jws = format!("{}.{}.{}", jws_header, jws_payload, jws_signature);
            ssi_jws::decode_verify(&reformed_jws, &pub_jwk_0).expect("pass");
        }
        // Ensure that alterations to the payload cause the verification to fail.
        {
            let (jws_header, _jws_payload, jws_signature) = ssi_jws::split_jws(&jws).expect("pass");
            // This is the base64-encoding of `{"HIPPOS":"much worse than OSTRICHES"}`
            let altered_jws_payload =
                format!("eyJISVBQT1MiOiJtdWNoIHdvcnNlIHRoYW4gT1NUUklDSEVTIn0");
            let altered_jws = format!("{}.{}.{}", jws_header, altered_jws_payload, jws_signature);
            ssi_jws::decode_verify(&altered_jws, &pub_jwk_0).expect_err("pass");
        }
    }
}

#[test]
fn test_did_document_metadata_roundtrip() {
    let creation_metadata_ov = vec![None, Some(CreationMetadata::new(now_utc_milliseconds()))];
    let next_update_metadata_ov = vec![
        None,
        Some(NextUpdateMetadata::new(now_utc_milliseconds(), 1)),
    ];
    let latest_update_metadata_ov = vec![
        None,
        Some(LatestUpdateMetadata::new(now_utc_milliseconds(), 2)),
    ];
    let deactivated_o = vec![None, Some(false), Some(true)];

    for creation_metadata_o in creation_metadata_ov.iter() {
        for next_update_metadata_o in next_update_metadata_ov.iter() {
            for latest_update_metadata_o in latest_update_metadata_ov.iter() {
                for deactivated_o in deactivated_o.iter() {
                    let did_document_metadata = DIDDocumentMetadata {
                        creation_metadata_o: creation_metadata_o.clone(),
                        next_update_metadata_o: next_update_metadata_o.clone(),
                        latest_update_metadata_o: latest_update_metadata_o.clone(),
                        deactivated_o: deactivated_o.clone(),
                    };
                    tracing::debug!("--------------------------------");
                    tracing::debug!("did_document_metadata: {:?}", did_document_metadata);
                    let did_document_metadata_str =
                        serde_json::to_string(&did_document_metadata).expect("pass");
                    tracing::debug!(
                        "did_document_metadata as json: {}",
                        did_document_metadata_str
                    );
                    let deserialized_did_document_metadata: DIDDocumentMetadata =
                        serde_json::from_str(&did_document_metadata_str).expect("pass");
                    tracing::debug!(
                        "deserialized_did_document_metadata: {:?}",
                        deserialized_did_document_metadata
                    );
                    assert_eq!(deserialized_did_document_metadata, did_document_metadata);
                }
            }
        }
    }
}

#[test]
fn produce_complete_did_documents_jsonl() {
    tracing::info!("Reading environment variables...");
    let vdr_create_endpoint_o = std::env::var("VDR_CREATE_ENDPOINT").ok();
    let produce_deactivated_did_o = std::env::var("PRODUCE_DEACTIVATED_DID").ok();
    tracing::info!(
        "VDR_CREATE_ENDPOINT: {}",
        if let Some(vdr_create_endpoint) = vdr_create_endpoint_o.as_ref() {
            vdr_create_endpoint
        } else {
            "not specified; using default: https://example.com"
        }
    );
    tracing::info!(
        "PRODUCE_DEACTIVATED_DID: {}",
        if let Some(produce_deactivated_did) = produce_deactivated_did_o.as_ref() {
            produce_deactivated_did
        } else {
            "not specified; using default: true"
        }
    );
    let vdr_create_endpoint = vdr_create_endpoint_o.unwrap_or("https://example.com".to_string());
    let produce_deactivated_did = produce_deactivated_did_o.unwrap_or("true".to_string());

    let vdr_create_endpoint_url = url::Url::parse(&vdr_create_endpoint)
        .expect("Malformed URL in env var VDR_CREATE_ENDPOINT");
    tracing::debug!("vdr_create_endpoint_url: {:?}", vdr_create_endpoint_url);

    let produce_deactivated_did = match produce_deactivated_did.as_str() {
        "true" => true,
        "false" => false,
        _ => panic!("env var PRODUCE_DEACTIVATED_DID must be true or false"),
    };
    if produce_deactivated_did {
        tracing::debug!("PRODUCE_DEACTIVATED_DID is true, so we will produce a deactivated DID");
    } else {
        tracing::debug!(
            "PRODUCE_DEACTIVATED_DID is false, so we will produce a non-deactivated DID"
        );
    }

    let did_hostname = vdr_create_endpoint_url
        .host_str()
        .expect("Expected host in env var VDR_CREATE_ENDPOINT");
    let did_port_o = vdr_create_endpoint_url.port();
    let did_path_o = if vdr_create_endpoint_url.path() == "/" {
        None
    } else {
        assert!(vdr_create_endpoint_url.path().starts_with("/"));
        Some(
            vdr_create_endpoint_url
                .path()
                .strip_prefix("/")
                .unwrap()
                .replace('/', ":"),
        )
    };

    let hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);

    // Initial set of verification method keys
    let signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    // This is the key to update the initial DID doc.
    let update_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_verifying_key_0 = update_signing_key_0.verifying_key();
    let update_pub_key_0 = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_verifying_key_0,
    );
    let did_document_0 = {
        let verifying_key_0 = signing_key_0.verifying_key();
        let pub_key_0 =
            mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_0);

        // Demonstrate non-hashed update key
        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: update_pub_key_0.clone(),
        });
        let valid_from = now_utc_milliseconds();
        let public_key_set = PublicKeySet {
            authentication_v: vec![&pub_key_0],
            assertion_method_v: vec![&pub_key_0],
            key_agreement_v: vec![&pub_key_0],
            capability_invocation_v: vec![&pub_key_0],
            capability_delegation_v: vec![&pub_key_0],
        };
        let mut did_document_0 = DIDDocument::create_unsigned_root(
            did_hostname,
            did_port_o,
            did_path_o.as_deref(),
            update_rules,
            valid_from,
            public_key_set,
            &hash_function,
        )
        .expect("pass");
        did_document_0.finalize(None).expect("pass");
        did_document_0.verify_root_nonrecursive().expect("pass");
        did_document_0
    };
    let did = did_document_0.did.deref();
    println!("{}", did.resolution_url_for_did_documents_jsonl(None));
    println!(
        "{}",
        serde_json_canonicalizer::to_string(&did_document_0).unwrap()
    );

    // Next set of verification method keys
    let signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    // This is the next update key
    let update_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_verifying_key_1 = update_signing_key_1.verifying_key();
    let update_pub_key_1 = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_verifying_key_1,
    );
    let did_document_1 = {
        let verifying_key_1 = signing_key_1.verifying_key();
        let pub_key_1 =
            mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_1);

        // Demonstrate hashed update key
        let update_rules =
            RootLevelUpdateRules::from(HashedUpdateKey::from_pub_key(&update_pub_key_1));
        let valid_from = now_utc_milliseconds();
        let public_key_set = PublicKeySet {
            authentication_v: vec![&pub_key_1],
            assertion_method_v: vec![&pub_key_1],
            key_agreement_v: vec![&pub_key_1],
            capability_invocation_v: vec![&pub_key_1],
            capability_delegation_v: vec![&pub_key_1],
        };
        let mut did_document_1 = DIDDocument::create_unsigned_non_root(
            &did_document_0,
            update_rules,
            valid_from,
            public_key_set,
            &hash_function,
        )
        .expect("pass");
        // Have to sign the update.
        {
            let jws = did_document_1
                .sign(update_pub_key_0.to_string(), &update_signing_key_0)
                .expect("pass");
            did_document_1.add_proof(jws.into_string());
        }
        did_document_1
            .finalize(Some(&did_document_0))
            .expect("pass");
        did_document_1
            .verify_non_root_nonrecursive(&did_document_0)
            .expect("pass");
        did_document_1
    };
    println!(
        "{}",
        serde_json_canonicalizer::to_string(&did_document_1).unwrap()
    );

    // Next set of verification method keys (these are used only if produce_deactivated_did is false)
    let signing_key_2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    // This is the next update key
    let update_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let update_verifying_key_2 = update_signing_key_2.verifying_key();
    let update_pub_key_2 = mbx::MBPubKey::from_ed25519_dalek_verifying_key(
        mbx::Base::Base64Url,
        &update_verifying_key_2,
    );
    let did_document_2 = {
        // These are used only if produce_deactivated_did is false
        let verifying_key_2 = signing_key_2.verifying_key();
        let pub_key_2 =
            mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &verifying_key_2);

        let (update_rules, public_key_set) = if produce_deactivated_did {
            // Demonstrate UpdatesDisallowed
            let update_rules = RootLevelUpdateRules::UpdatesDisallowed(UpdatesDisallowed {});
            let public_key_set = PublicKeySet {
                authentication_v: vec![],
                assertion_method_v: vec![],
                key_agreement_v: vec![],
                capability_invocation_v: vec![],
                capability_delegation_v: vec![],
            };
            (update_rules, public_key_set)
        } else {
            let update_rules =
                RootLevelUpdateRules::from(HashedUpdateKey::from_pub_key(&update_pub_key_2));

            let public_key_set = PublicKeySet {
                authentication_v: vec![&pub_key_2],
                assertion_method_v: vec![&pub_key_2],
                key_agreement_v: vec![&pub_key_2],
                capability_invocation_v: vec![&pub_key_2],
                capability_delegation_v: vec![&pub_key_2],
            };
            (update_rules, public_key_set)
        };
        let valid_from = now_utc_milliseconds();
        let mut did_document_2 = DIDDocument::create_unsigned_non_root(
            &did_document_1,
            update_rules,
            valid_from,
            public_key_set,
            &hash_function,
        )
        .expect("pass");
        // Have to sign the update.
        {
            let jws = did_document_2
                .sign(update_pub_key_1.to_string(), &update_signing_key_1)
                .expect("pass");
            did_document_2.add_proof(jws.into_string());
        }
        did_document_2
            .finalize(Some(&did_document_1))
            .expect("pass");
        did_document_2
            .verify_non_root_nonrecursive(&did_document_1)
            .expect("pass");
        did_document_2
    };
    println!(
        "{}",
        serde_json_canonicalizer::to_string(&did_document_2).unwrap()
    );
}
