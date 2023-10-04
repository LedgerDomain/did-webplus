use std::str::FromStr;

use did_webplus::{DIDDocument, DIDDocumentCreateParams, DIDDocumentUpdateParams, PublicKeySet};
use selfhash::HashFunction;
use selfsign::SelfSignAndHashable;

#[test]
#[serial_test::serial]
fn test_roundtrip_did_basic() {
    let str_v = [
        "did:webplus:example.com:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ",
        "did:webplus:example.com:user:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ",
        "did:webplus:example.com:user:thingy:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ",
    ];
    for s in str_v {
        let did = did_webplus::DID::from_str(s).expect("pass");
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
    let str_v = [
        "did:webplus:example.com:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz",
        "did:webplus:example.com:user:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz",
        "did:webplus:example.com:user:thingy:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz",
    ];
    for s in str_v {
        let did = did_webplus::DIDWithQuery::from_str(s).expect("pass");
        println!("string form of DID: {}", s);
        println!("parsed DID: {:?}", did);
        let s2 = did.to_string();
        println!("re-stringed form of DID: {}", s);
        assert_eq!(s, &s2);
    }
}

#[test]
#[serial_test::serial]
fn test_roundtrip_did_with_query_and_key_id_fragment() {
    let str_v = [
        "did:webplus:example.com:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU",
        "did:webplus:example.com:user:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU",
        "did:webplus:example.com:user:thingy:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU",
    ];
    for s in str_v {
        let did = did_webplus::DIDWithQueryAndKeyIdFragment::from_str(s).expect("pass");
        println!("string form of DID: {}", s);
        println!("parsed DID: {:?}", did);
        let s2 = did.to_string();
        println!("re-stringed form of DID: {}", s);
        assert_eq!(s, &s2);
    }
}

#[test]
#[serial_test::serial]
fn test_roundtrip_did_with_key_id_fragment() {
    let str_v = [
        "did:webplus:example.com:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU",
        "did:webplus:example.com:user:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU",
        "did:webplus:example.com:user:thingy:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU",
    ];
    for s in str_v {
        let did = did_webplus::DIDWithKeyIdFragment::from_str(s).expect("pass");
        println!("string form of DID: {}", s);
        println!("parsed DID: {:?}", did);
        let s2 = did.to_string();
        println!("re-stringed form of DID: {}", s);
        assert_eq!(s, &s2);
    }
}

#[test]
#[serial_test::serial]
fn test_root_did_document_self_sign() {
    let ed25519_signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_signing_key_1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_0 = ed25519_signing_key_0.verifying_key();
    let ed25519_verifying_key_1 = ed25519_signing_key_1.verifying_key();
    // To create a root DIDDocument from the controller side, we only supply:
    // - The did:webplus value with a placeholder self-signature
    // - The valid_from timestamp at which the DID document becomes valid.
    // - The public keys for each key purpose
    let root_did_document = DIDDocument::create_root(
        DIDDocumentCreateParams {
            did_host: "example.com".into(),
            did_path_o: None,
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                // Note that this is the one being used to self-sign the root DIDDocument.
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_0],
            },
        },
        &selfhash::Blake3,
        &ed25519_signing_key_1,
    )
    .expect("pass");
    root_did_document
        .verify_self_signatures_and_hashes()
        .expect("pass");

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
    // To create a root DIDDocument from the controller side, we only supply:
    // - The did:webplus value with a placeholder self-signature
    // - The valid_from timestamp at which the DID document becomes valid.
    // - The public keys for each key purpose
    let did_document_0 = DIDDocument::create_root(
        DIDDocumentCreateParams {
            did_host: "localhost".into(),
            // did_path_o: Some("user".into()),
            did_path_o: None,
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                // Note that this is the one being used to self-sign the root DIDDocument.
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_0],
            },
        },
        &selfhash::Blake3,
        &ed25519_signing_key_1,
    )
    .expect("pass");
    println!(
        "did_document_0:\n{}",
        serde_json::to_string_pretty(&did_document_0).unwrap()
    );
    println!(
        "did_document_0 in JCS format:\n{}",
        std::str::from_utf8(
            did_document_0
                .serialize_canonically_to_vec()
                .expect("pass")
                .as_slice()
        )
        .expect("pass")
    );
    did_document_0
        .verify_self_signatures_and_hashes()
        .expect("pass");
    did_document_0.verify_root_nonrecursive().expect("pass");

    // Now create a second DID document, which is a non-root DID document.  Create another key to be rotated in.
    let ed25519_signing_key_2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_2 = ed25519_signing_key_2.verifying_key();
    let did_document_1 = DIDDocument::update_from_previous(
        &did_document_0,
        DIDDocumentUpdateParams {
            valid_from: time::OffsetDateTime::now_utc(),
            public_key_set: PublicKeySet {
                authentication_v: vec![&ed25519_verifying_key_0, &ed25519_verifying_key_2],
                assertion_method_v: vec![&ed25519_verifying_key_0],
                key_agreement_v: vec![&ed25519_verifying_key_0],
                capability_invocation_v: vec![&ed25519_verifying_key_1],
                capability_delegation_v: vec![&ed25519_verifying_key_2],
            },
        },
        selfhash::Blake3.new_hasher(),
        &ed25519_signing_key_1,
    )
    .expect("pass");
    println!(
        "did_document_1:\n{}",
        serde_json::to_string_pretty(&did_document_1).unwrap()
    );
    println!(
        "did_document_1 in JCS format:\n{}",
        std::str::from_utf8(
            did_document_1
                .serialize_canonically_to_vec()
                .expect("pass")
                .as_slice()
        )
        .expect("pass")
    );
    did_document_1
        .verify_self_signatures_and_hashes()
        .expect("pass");
    did_document_1
        .verify_non_root_nonrecursive(&did_document_0)
        .expect("pass");

    // Attempt to make an update using a key not listed in capability_invocation_v, and see that it fails.
    let ed25519_signing_key_attacker = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let ed25519_verifying_key_attacker = ed25519_signing_key_attacker.verifying_key();
    DIDDocument::update_from_previous(
        &did_document_1,
        DIDDocumentUpdateParams {
            valid_from: time::OffsetDateTime::now_utc(),
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
        selfhash::Blake3.new_hasher(),
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
fn test_signature_generation_with_witness() {
    let signing_key_0 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_0 = signing_key_0.verifying_key();
    let mut priv_jwk_0 = priv_jwk_from_ed25519_signing_key(&signing_key_0);

    println!("# Example: Signature Generation With Witness\n\nThis example can be run via command:\n\n    cargo test --all-features -- --nocapture test_signature_generation_with_witness\n\nBy specifying the `versionId` and `selfHash` query params in the `kid` field of a signature (header), the signer is committing to a specific DID document version having a specific `selfHash` value.  This acts as a witness in a limited way, making forking a DID microledger much more difficult.  Note that use of a Verifiable Data Gateway (described elsewhere) is the recommended way for preventing signature repudiation and forking of DIDs.\n");

    // TODO: Other key types
    {
        println!("## Key Generation and DID Creation\n\nWe generate a private key and create a DID using the public key for the verification methods.  The generated private key is:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_0).expect("pass"));

        let did_document_0 = DIDDocument::create_root(
            DIDDocumentCreateParams {
                did_host: "example.com".into(),
                did_path_o: None,
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
        .expect("pass");
        did_document_0
            .verify_self_signatures_and_hashes()
            .expect("pass");
        let did = did_document_0.did.clone();
        println!(
            "Root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):\n\n```json\n{}\n```\n",
            serde_json::to_string_pretty(&did_document_0).unwrap()
        );
        did_document_0.verify_root_nonrecursive().expect("pass");
        use selfsign::Verifier;
        // Add query params for versionId and selfHash, so that the signature produced with this key commits
        // the DID document with the given versionId to have the given selfHash.  This manifests a limited
        // form of witnessing.
        let did_with_query_and_key_id_fragment = did
            .with_query(format!(
                "versionId={}&selfHash={}",
                did_document_0.version_id,
                did_document_0.self_hash_o.as_ref().unwrap()
            ))
            .with_fragment(verifying_key_0.to_keri_verifier().into_owned());
        // Set the key_id field of the JWK, so that it appears in the header of JWS signatures.
        priv_jwk_0.key_id = Some(did_with_query_and_key_id_fragment.to_string());
        println!("We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:\n\n```json\n{}\n```\n", serde_json::to_string_pretty(&priv_jwk_0).expect("pass"));

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
