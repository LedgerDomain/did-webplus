use did_webplus::{
    DIDDocumentCreateParams, DIDDocumentTrait, DIDDocumentUpdateParams, Microledger,
    NonRootDIDDocument, PublicKeySet, RootDIDDocument,
};
use selfsign::Verifier;

#[test]
#[serial_test::serial]
fn test_root_did_document_self_sign() {
    let ed25519_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_0 = ed25519_signing_key_0.verifying_key();
    let ed25519_verifying_key_1 = ed25519_signing_key_1.verifying_key();
    // To create a RootDIDDocument from the controller side, we only supply:
    // - The did:webplus value with a placeholder self-signature
    // - The valid_from timestamp at which the DID document becomes valid.
    // - The public keys for each key purpose
    let root_did_document = RootDIDDocument::create(
        DIDDocumentCreateParams {
            did_webplus_host: "example.com".into(),
            valid_from: chrono::Utc::now(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                // Note that this is the one being used to self-sign the RootDIDDocument.
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_0],
            },
        },
        &ed25519_signing_key_1,
    )
    .expect("pass");
    use selfsign::SelfSignable;
    root_did_document.verify_self_signatures().expect("pass");

    println!(
        "root did_document:\n{}",
        serde_json::to_string_pretty(&root_did_document).unwrap()
    );
}

#[test]
#[serial_test::serial]
fn test_did_document_verification() {
    let ed25519_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_0 = ed25519_signing_key_0.verifying_key();
    let ed25519_verifying_key_1 = ed25519_signing_key_1.verifying_key();
    // To create a RootDIDDocument from the controller side, we only supply:
    // - The did:webplus value with a placeholder self-signature
    // - The valid_from timestamp at which the DID document becomes valid.
    // - The public keys for each key purpose
    let did_document_0 = RootDIDDocument::create(
        DIDDocumentCreateParams {
            did_webplus_host: "example.com".into(),
            valid_from: chrono::Utc::now(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                // Note that this is the one being used to self-sign the RootDIDDocument.
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_0],
            },
        },
        &ed25519_signing_key_1,
    )
    .expect("pass");
    println!(
        "did_document_0:\n{}",
        serde_json::to_string_pretty(&did_document_0).unwrap()
    );
    use selfsign::SelfSignable;
    did_document_0.verify_self_signatures().expect("pass");
    use did_webplus::DIDDocumentTrait;
    did_document_0.verify_root().expect("pass");

    // Now create a second DID document, which is a non-root DID document.  Create another key to be rotated in.
    let ed25519_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_2 = ed25519_signing_key_2.verifying_key();
    let did_document_1 = NonRootDIDDocument::update_from_previous(
        Box::new(&did_document_0),
        DIDDocumentUpdateParams {
            valid_from: chrono::Utc::now(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0, &ed25519_verifying_key_2],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_2],
            },
        },
        &ed25519_signing_key_1,
    )
    .expect("pass");
    println!(
        "did_document_1:\n{}",
        serde_json::to_string_pretty(&did_document_1).unwrap()
    );
    did_document_1.verify_self_signatures().expect("pass");
    did_document_1
        .verify_non_root_nonrecursive(Box::new(&did_document_0))
        .expect("pass");

    // Attempt to make an update using a key not listed in capability_invocation_v, and see that it fails.
    let ed25519_signing_key_attacker = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_attacker = ed25519_signing_key_attacker.verifying_key();
    NonRootDIDDocument::update_from_previous(
        Box::new(&did_document_1),
        DIDDocumentUpdateParams {
            valid_from: chrono::Utc::now(),
            public_key_set: PublicKeySet {
                authentication_v: vec![
                    &ed25519_verifying_key_0,
                    &ed25519_verifying_key_2,
                    &ed25519_verifying_key_attacker,
                ],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_2],
            },
        },
        &ed25519_signing_key_attacker,
    )
    .expect_err("pass");
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
fn test_signature_generation() {
    let ed25519_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();
    let mut ed25519_priv_jwk = priv_jwk_from_ed25519_signing_key(&ed25519_signing_key);

    // TODO: Other key types
    {
        let did_document_0 = RootDIDDocument::create(
            DIDDocumentCreateParams {
                did_webplus_host: "example.com".into(),
                valid_from: chrono::Utc::now(),
                public_key_set: PublicKeySet {
                    authentication_v: vec![&ed25519_verifying_key],
                    assertion_method_v: vec![&ed25519_verifying_key],
                    key_agreement_v: vec![&ed25519_verifying_key],
                    // Note that this is the one being used to self-sign the RootDIDDocument.
                    capability_invocation_v: vec![&ed25519_verifying_key],
                    capability_delegation_v: vec![&ed25519_verifying_key],
                },
            },
            &ed25519_signing_key,
        )
        .expect("pass");
        use selfsign::SelfSignable;
        did_document_0.verify_self_signatures().expect("pass");
        let did = did_document_0.id.clone();
        println!(
            "root did_document:\n{}",
            serde_json::to_string_pretty(&did_document_0).unwrap()
        );
        did_document_0.verify_root().expect("pass");
        let did_webplus_with_key_id_fragment =
            did.with_fragment(ed25519_verifying_key.to_keri_verifier().into_owned());

        // Add query params for versionId and hl (which is set to the current DID document's self-signature),
        // so that the signature produced with this key commits the DID document with the given versionId to have
        // the given self-signature.
        let did_webplus_with_query_and_key_id_fragment = did_webplus_with_key_id_fragment
            .with_query(format!(
                "versionId={}&hl={}",
                did_document_0.version_id,
                did_document_0.self_signature_o.as_ref().unwrap()
            ));
        ed25519_priv_jwk.key_id = Some(did_webplus_with_query_and_key_id_fragment.to_string());
        // Sign stuff.
        let message = b"HIPPOS are much better than OSTRICHES";
        let jws = ssi_jws::detached_sign_unencoded_payload(
            ed25519_priv_jwk.get_algorithm().expect("pass"),
            message,
            &ed25519_priv_jwk,
        )
        .expect("pass");
        println!("jws: {}", jws);
        // Verify signature.
        let ed25519_pub_jwk = ed25519_priv_jwk.to_public();
        let jws_header = ssi_jws::detached_verify(&jws, message, &ed25519_pub_jwk).expect("pass");
        println!(
            "jws header:\n{}",
            serde_json::to_string_pretty(&jws_header).unwrap()
        );
        ssi_jws::detached_verify(&jws, b"fake payload, this should fail", &ed25519_pub_jwk)
            .expect_err("pass");
    }
}

#[test]
#[serial_test::serial]
fn test_microledger() {
    println!("-- TESTING MICROLEDGER ---------------------------------\n");

    let ed25519_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_0 = ed25519_signing_key_0.verifying_key();
    let ed25519_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_1 = ed25519_signing_key_1.verifying_key();

    // Create a DID and its associated Microledger
    let (mut microledger, _ed25519_priv_jwk_0) = {
        let microledger = Microledger::create(
            RootDIDDocument::create(
                DIDDocumentCreateParams {
                    did_webplus_host: "example.com".into(),
                    valid_from: chrono::Utc::now(),
                    public_key_set: PublicKeySet {
                        authentication_v: vec![&ed25519_verifying_key_0],
                        assertion_method_v: vec![&ed25519_verifying_key_0],
                        key_agreement_v: vec![&ed25519_verifying_key_0],
                        // Note that this is the one being used to self-sign the RootDIDDocument.
                        capability_invocation_v: vec![&ed25519_verifying_key_0],
                        capability_delegation_v: vec![&ed25519_verifying_key_0],
                    },
                },
                &ed25519_signing_key_0,
            )
            .expect("pass"),
        )
        .expect("pass");
        let did = microledger.did().clone();
        println!("did: {}", did);
        let did_webplus_with_key_id_fragment =
            did.with_fragment(ed25519_verifying_key_0.to_keri_verifier().into_owned());
        let mut ed25519_priv_jwk_0 = priv_jwk_from_ed25519_signing_key(&ed25519_signing_key_0);
        ed25519_priv_jwk_0.key_id = Some(did_webplus_with_key_id_fragment.to_string());
        println!(
            "ed25519_priv_jwk: {}",
            serde_json::to_string(&ed25519_priv_jwk_0).expect("pass")
        );
        let latest_did_document_b = microledger.latest_did_document();
        println!(
            "latest DID document (which by construction is the root):\n{}",
            latest_did_document_b.to_json_pretty(),
        );
        println!(
            "latest DID document metadata:\n{:#?}",
            microledger.did_document_metadata_for(Box::new(latest_did_document_b))
        );
        (microledger, ed25519_priv_jwk_0)
    };

    println!("\n-- updating microledger -----------------------------------------------\n");
    // Update the Microledger.
    let _ed25519_priv_jwk_1 = {
        microledger
            .update_as_controller(
                DIDDocumentUpdateParams {
                    valid_from: chrono::Utc::now(),
                    public_key_set: PublicKeySet {
                        authentication_v: vec![&ed25519_verifying_key_0, &ed25519_verifying_key_1],
                        assertion_method_v: vec![&ed25519_verifying_key_0],
                        key_agreement_v: vec![&ed25519_verifying_key_1],
                        capability_invocation_v: vec![&ed25519_verifying_key_0],
                        capability_delegation_v: vec![&ed25519_verifying_key_0],
                    },
                },
                &ed25519_signing_key_0,
            )
            .expect("pass");
        let did = microledger.did().clone();
        println!("did: {}", did);
        let did_webplus_with_key_id_fragment =
            did.with_fragment(ed25519_verifying_key_0.to_keri_verifier().into_owned());
        let mut ed25519_priv_jwk_1 = priv_jwk_from_ed25519_signing_key(&ed25519_signing_key_0);
        ed25519_priv_jwk_1.key_id = Some(did_webplus_with_key_id_fragment.to_string());
        println!(
            "ed25519_priv_jwk: {}",
            serde_json::to_string(&ed25519_priv_jwk_1).expect("pass")
        );
        println!(
            "root DID document metadata:\n{:#?}",
            microledger.did_document_metadata_for(Box::new(microledger.root_did_document()))
        );
        let latest_did_document_b = microledger.latest_did_document();
        println!(
            "latest DID document (which by construction is the second):\n{}",
            latest_did_document_b.to_json_pretty(),
        );
        println!(
            "latest DID document metadata:\n{:#?}",
            microledger.did_document_metadata_for(Box::new(latest_did_document_b))
        );
        ed25519_priv_jwk_1
    };

    println!("\n-- results -----------------------------------------------\n");

    println!(
        "root DID document:\n{}",
        serde_json::to_string_pretty(microledger.root_did_document()).expect("pass")
    );
    println!(
        "root DID document metadata:\n{}",
        serde_json::to_string_pretty(
            &microledger.did_document_metadata_for(Box::new(microledger.root_did_document()))
        )
        .expect("pass")
    );
    for non_root_microledger_node in microledger.non_root_did_document_v() {
        println!(
            "non-root DID document:\n{}",
            serde_json::to_string_pretty(&non_root_microledger_node).expect("pass")
        );
        println!(
            "non-root DID document metadata:\n{}",
            serde_json::to_string_pretty(
                &microledger.did_document_metadata_for(Box::new(non_root_microledger_node))
            )
            .expect("pass")
        );
    }

    // TODO:
    // // Now have an "external" party pull the Microledger one node at a time, verifying it as it goes.
    // let mut external_microledger = Microledger::create()
}
