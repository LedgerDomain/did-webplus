use std::collections::HashMap;

use did_webplus::{
    said_placeholder, said_placeholder_for_uri, DIDDocument, DIDWebplus, DIDWebplusWithFragment,
    KeyMaterial, Microledger, NonRootDIDDocument, NonRootDIDDocumentParams, PublicKeyJWK,
    PublicKeyParams, PublicKeyParamsEC, PublicKeyParamsOKP, RootDIDDocument, RootDIDDocumentParams,
    VerificationMethod, SAID_HASH_FUNCTION_CODE,
};

#[test]
#[serial_test::serial]
fn test_said_placeholder() {
    for hash_function_code in [
        said::derivation::HashFunctionCode::Blake3_256,
        said::derivation::HashFunctionCode::Blake2B256(vec![]),
        said::derivation::HashFunctionCode::Blake2S256(vec![]),
        said::derivation::HashFunctionCode::SHA3_256,
        said::derivation::HashFunctionCode::SHA2_256,
        said::derivation::HashFunctionCode::Blake3_512,
        said::derivation::HashFunctionCode::SHA3_512,
        said::derivation::HashFunctionCode::Blake2B512,
        said::derivation::HashFunctionCode::SHA2_512,
    ] {
        let placeholder = said_placeholder(&hash_function_code);
        use said::sad::DerivationCode;
        assert_eq!(placeholder.len(), hash_function_code.clone().full_size());
    }
}

#[test]
#[serial_test::serial]
fn test_said_placeholder_for_uri() {
    for hash_function_code in [
        said::derivation::HashFunctionCode::Blake3_256,
        said::derivation::HashFunctionCode::Blake2B256(vec![]),
        said::derivation::HashFunctionCode::Blake2S256(vec![]),
        said::derivation::HashFunctionCode::SHA3_256,
        said::derivation::HashFunctionCode::SHA2_256,
        said::derivation::HashFunctionCode::Blake3_512,
        said::derivation::HashFunctionCode::SHA3_512,
        said::derivation::HashFunctionCode::Blake2B512,
        said::derivation::HashFunctionCode::SHA2_512,
    ] {
        let placeholder = said_placeholder_for_uri(&hash_function_code);
        use said::sad::DerivationCode;
        assert_eq!(placeholder.len(), hash_function_code.full_size());
        let _ = DIDWebplus::with_host("example.com").expect("pass");
    }
}

#[test]
#[serial_test::serial]
fn test_did_webplus_said() {
    use did_webplus::DIDWebplus;

    // This is a bit of a silly test, since it only forms the SAID for "did:webplus:example.com:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".
    let mut did_webplus = DIDWebplus::with_host("example.com").unwrap();
    println!("did_webplus: {}", did_webplus);
    use said::sad::SAD;
    did_webplus.compute_digest();
    println!("did_webplus: {}", did_webplus);
}

// TODO: Deprecate this
#[test]
#[serial_test::serial]
fn test_did_document_said() {
    let did = DIDWebplus::with_host("example.com").unwrap();
    let mut did_document = DIDDocument {
        id: did.clone(),
        prev_did_document_hash_o: None,
        valid_from: chrono::Utc::now(),
        version_id: 0,
        verification_method_v: vec![
            VerificationMethod::json_web_key_2020(
                did.with_fragment("key-1").expect("pass"),
                public_key_params_ec_example_secp256k1().into(),
            ),
            VerificationMethod::json_web_key_2020(
                did.with_fragment("key-2").expect("pass"),
                public_key_params_okp_example_ed25519().into(),
            ),
        ],
        authentication_fragment_v: vec!["#key-1".into()],
        assertion_method_fragment_v: vec!["#key-2".into()],
        key_agreement_fragment_v: vec!["#key-1".into()],
        capability_invocation_fragment_v: vec!["#key-2".into()],
        capability_delegation_fragment_v: vec!["#key-1".into()],
    };
    println!(
        "did_document:\n{}",
        serde_json::to_string_pretty(&did_document).unwrap()
    );
    use said::sad::SAD;
    println!(
        "did_document.derivation_data: {}",
        String::from_utf8_lossy(did_document.derivation_data().as_slice())
    );
    did_document.compute_digest();
    println!(
        "did_document:\n{}",
        serde_json::to_string_pretty(&did_document).unwrap()
    );
}

// TODO: Deprecate this
#[test]
#[serial_test::serial]
fn test_did_document_verification() {
    let did = DIDWebplus::with_host("example.com").unwrap();
    let mut did_document_0 = DIDDocument {
        id: did.clone(),
        prev_did_document_hash_o: None,
        valid_from: chrono::Utc::now(),
        version_id: 0,
        verification_method_v: vec![VerificationMethod::json_web_key_2020(
            did.with_fragment("key-1").expect("pass"),
            public_key_params_ec_example_secp256k1().into(),
        )],
        authentication_fragment_v: vec!["#key-1".into()],
        assertion_method_fragment_v: vec!["#key-1".into()],
        key_agreement_fragment_v: vec!["#key-1".into()],
        capability_invocation_fragment_v: vec!["#key-1".into()],
        capability_delegation_fragment_v: vec!["#key-1".into()],
    };
    // The initial DID document is what produces the SAID.
    use said::sad::SAD;
    did_document_0.compute_digest();
    // Extract the DID from the DID document.
    let did = did_document_0.id.clone();
    println!("did: {}", did);
    println!(
        "did_document_0:\n{}",
        serde_json::to_string_pretty(&did_document_0).unwrap()
    );
    did_document_0.verify_initial().expect("pass");
    let did_document_0_hash = did_document_0.hash(&SAID_HASH_FUNCTION_CODE);

    let did_document_1 = DIDDocument {
        id: did.clone(),
        prev_did_document_hash_o: Some(did_document_0_hash.clone()),
        valid_from: chrono::Utc::now(),
        version_id: 1,
        verification_method_v: vec![
            VerificationMethod::json_web_key_2020(
                did.with_fragment("key-1").expect("pass"),
                public_key_params_ec_example_secp256k1().into(),
            ),
            VerificationMethod::json_web_key_2020(
                did.with_fragment("key-2").expect("pass"),
                public_key_params_okp_example_ed25519().into(),
            ),
        ],
        authentication_fragment_v: vec!["#key-1".into()],
        assertion_method_fragment_v: vec!["#key-2".into()],
        key_agreement_fragment_v: vec!["#key-1".into()],
        capability_invocation_fragment_v: vec!["#key-2".into()],
        capability_delegation_fragment_v: vec!["#key-1".into()],
    };
    did_document_1
        .verify_non_initial(&did_document_0)
        .expect("pass");
    println!(
        "did_document_1:\n{}",
        serde_json::to_string_pretty(&did_document_1).unwrap()
    );
    let did_document_1_hash = did_document_1.hash(&SAID_HASH_FUNCTION_CODE);

    let did_document_m = {
        let mut m = HashMap::new();
        m.insert(did_document_0_hash.clone(), did_document_0);
        m.insert(did_document_1_hash.clone(), did_document_1.clone());
        m
    };
    did_document_1
        .verify_did_microledger(&did_document_m)
        .expect("pass");
}

#[test]
#[serial_test::serial]
fn test_root_did_document_said() {
    let did = DIDWebplus::with_host("example.com").unwrap();
    let mut root_did_document = RootDIDDocument {
        id: did.clone(),
        said_o: None,
        valid_from: chrono::Utc::now(),
        version_id: 0,
        key_material: KeyMaterial {
            verification_method_v: vec![
                VerificationMethod::json_web_key_2020(
                    did.with_fragment("key-1").expect("pass"),
                    public_key_params_ec_example_secp256k1().into(),
                ),
                VerificationMethod::json_web_key_2020(
                    did.with_fragment("key-2").expect("pass"),
                    public_key_params_okp_example_ed25519().into(),
                ),
            ],
            authentication_fragment_v: vec!["#key-1".into()],
            assertion_method_fragment_v: vec!["#key-2".into()],
            key_agreement_fragment_v: vec!["#key-1".into()],
            capability_invocation_fragment_v: vec!["#key-2".into()],
            capability_delegation_fragment_v: vec!["#key-1".into()],
        },
    };
    println!(
        "root did_document:\n{}",
        serde_json::to_string_pretty(&root_did_document).unwrap()
    );
    use said::sad::SAD;
    println!(
        "root did_document.derivation_data: {}",
        String::from_utf8_lossy(root_did_document.derivation_data().as_slice())
    );
    root_did_document.compute_digest();
    println!(
        "root did_document:\n{}",
        serde_json::to_string_pretty(&root_did_document).unwrap()
    );
}

#[test]
#[serial_test::serial]
fn test_did_document_verification_2() {
    let did = DIDWebplus::with_host("example.com").unwrap();
    let mut did_document_0 = RootDIDDocument {
        id: did.clone(),
        said_o: None,
        valid_from: chrono::Utc::now(),
        version_id: 0,
        key_material: KeyMaterial {
            verification_method_v: vec![VerificationMethod::json_web_key_2020(
                did.with_fragment("key-1").expect("pass"),
                public_key_params_ec_example_secp256k1().into(),
            )],
            authentication_fragment_v: vec!["#key-1".into()],
            assertion_method_fragment_v: vec!["#key-1".into()],
            key_agreement_fragment_v: vec!["#key-1".into()],
            capability_invocation_fragment_v: vec!["#key-1".into()],
            capability_delegation_fragment_v: vec!["#key-1".into()],
        },
    };
    // The initial DID document is what produces the DID.
    use said::sad::SAD;
    did_document_0.compute_digest();
    // Extract the DID from the DID document.
    let did = did_document_0.id.clone();
    println!("did: {}", did);
    println!(
        "did_document_0:\n{}",
        serde_json::to_string_pretty(&did_document_0).unwrap()
    );
    use did_webplus::DIDDocumentTrait;
    did_document_0.verify_root().expect("pass");

    let mut did_document_1 = NonRootDIDDocument {
        id: did.clone(),
        said_o: None,
        prev_did_document_said: did_document_0.said_o.as_ref().unwrap().clone(),
        valid_from: chrono::Utc::now(),
        version_id: 1,
        key_material: KeyMaterial {
            verification_method_v: vec![
                VerificationMethod::json_web_key_2020(
                    did.with_fragment("key-1").expect("pass"),
                    public_key_params_ec_example_secp256k1().into(),
                ),
                VerificationMethod::json_web_key_2020(
                    did.with_fragment("key-2").expect("pass"),
                    public_key_params_okp_example_ed25519().into(),
                ),
            ],
            authentication_fragment_v: vec!["#key-1".into()],
            assertion_method_fragment_v: vec!["#key-2".into()],
            key_agreement_fragment_v: vec!["#key-1".into()],
            capability_invocation_fragment_v: vec!["#key-2".into()],
            capability_delegation_fragment_v: vec!["#key-1".into()],
        },
    };
    // This will populate the said_o field.
    did_document_1.compute_digest();
    println!(
        "did_document_1:\n{}",
        serde_json::to_string_pretty(&did_document_1).unwrap()
    );
    did_document_1
        .verify_non_root(Box::new(&did_document_0))
        .expect("pass");
}

// TODO: Deprecate this.
#[test]
#[serial_test::serial]
fn test_signature_generation() {
    for (key_type_str, generate_key_pair) in std::iter::zip(
        ["secp256k1", "ed25519"],
        [secp256k1_generate_key_pair, ed25519_generate_key_pair],
    ) {
        println!(
            "-- TESTING JWS for {} ---------------------------------",
            key_type_str
        );
        let did = DIDWebplus::with_host("example.com").unwrap();
        let fragment = "key-1";
        let did_with_fragment = did.with_fragment(fragment).expect("pass");
        let relative_did_with_fragment = format!("#{}", fragment);
        let (verification_method, mut priv_jwk) = generate_key_pair(did_with_fragment);
        let mut did_document_0 = DIDDocument {
            id: did.clone(),
            prev_did_document_hash_o: None,
            valid_from: chrono::Utc::now(),
            version_id: 0,
            verification_method_v: vec![verification_method],
            authentication_fragment_v: vec![relative_did_with_fragment.clone()],
            assertion_method_fragment_v: vec![relative_did_with_fragment.clone()],
            key_agreement_fragment_v: vec![relative_did_with_fragment.clone()],
            capability_invocation_fragment_v: vec![relative_did_with_fragment.clone()],
            capability_delegation_fragment_v: vec![relative_did_with_fragment.clone()],
        };
        // The initial DID document is what produces the SAID.
        use said::sad::SAD;
        did_document_0.compute_digest();
        // Extract the DID from the DID document.
        let did = did_document_0.id.clone();
        let did_with_fragment = did.with_fragment(fragment).expect("pass");
        println!("did: {}", did);
        println!("did_with_fragment: {}", did_with_fragment);
        println!(
            "did_document_0:\n{}",
            serde_json::to_string_pretty(&did_document_0).unwrap()
        );
        did_document_0.verify_initial().expect("pass");
        let did_document_0_hash = did_document_0.hash(&SAID_HASH_FUNCTION_CODE);
        println!("did_document_0_hash: {}", did_document_0_hash);

        // Add query params for versionId and hl, so that the signature produced with this key
        // commits the DID document with the given versionId to have the given hash.
        let did_with_query_and_fragment = did_with_fragment
            .with_query(
                format!(
                    "versionId={}&hl={}",
                    did_document_0.version_id, did_document_0_hash
                )
                .as_str(),
            )
            .expect("pass");
        priv_jwk.key_id = Some(did_with_query_and_fragment.clone().into_string());
        // Sign stuff.
        let message = b"HIPPOS are much better than OSTRICHES";
        let jws = ssi_jws::detached_sign_unencoded_payload(
            priv_jwk.get_algorithm().expect("pass"),
            message,
            &priv_jwk,
        )
        .expect("pass");
        println!("jws: {}", jws);
        // Verify signature.
        let pub_jwk = priv_jwk.to_public();
        let jws_header = ssi_jws::detached_verify(&jws, message, &pub_jwk).expect("pass");
        println!(
            "jws header:\n{}",
            serde_json::to_string_pretty(&jws_header).unwrap()
        );
        ssi_jws::detached_verify(&jws, b"fake payload, this should fail", &pub_jwk)
            .expect_err("pass");
    }
}

#[test]
#[serial_test::serial]
fn test_signature_generation_2() {
    for (key_type_str, generate_key_pair) in std::iter::zip(
        ["secp256k1", "ed25519"],
        [secp256k1_generate_key_pair, ed25519_generate_key_pair],
    ) {
        println!(
            "-- TESTING JWS for {} ---------------------------------",
            key_type_str
        );
        let did = DIDWebplus::with_host("example.com").unwrap();
        let fragment = "key-1";
        let did_with_fragment = did.with_fragment(fragment).expect("pass");
        let relative_did_with_fragment = format!("#{}", fragment);
        let (verification_method, mut priv_jwk) = generate_key_pair(did_with_fragment);
        let mut did_document_0 = RootDIDDocument {
            id: did.clone(),
            said_o: None,
            valid_from: chrono::Utc::now(),
            version_id: 0,
            key_material: KeyMaterial {
                verification_method_v: vec![verification_method],
                authentication_fragment_v: vec![relative_did_with_fragment.clone()],
                assertion_method_fragment_v: vec![relative_did_with_fragment.clone()],
                key_agreement_fragment_v: vec![relative_did_with_fragment.clone()],
                capability_invocation_fragment_v: vec![relative_did_with_fragment.clone()],
                capability_delegation_fragment_v: vec![relative_did_with_fragment.clone()],
            },
        };
        // The initial DID document is what produces the DID.
        use said::sad::SAD;
        did_document_0.compute_digest();
        // Extract the DID from the DID document.
        let did = did_document_0.id.clone();
        let did_with_fragment = did.with_fragment(fragment).expect("pass");
        println!("did: {}", did);
        println!("did_with_fragment: {}", did_with_fragment);
        println!(
            "did_document_0:\n{}",
            serde_json::to_string_pretty(&did_document_0).unwrap()
        );
        use did_webplus::DIDDocumentTrait;
        did_document_0.verify_root().expect("pass");

        // Add query params for versionId and hl (which is set to the current DID document's SAID), so that
        // the signature produced with this key commits the DID document with the given versionId to have
        // the given SAID.
        let did_with_query_and_fragment = did_with_fragment
            .with_query(
                format!(
                    "versionId={}&hl={}",
                    did_document_0.version_id,
                    did_document_0.said_o.as_ref().unwrap()
                )
                .as_str(),
            )
            .expect("pass");
        priv_jwk.key_id = Some(did_with_query_and_fragment.clone().into_string());
        // Sign stuff.
        let message = b"HIPPOS are much better than OSTRICHES";
        let jws = ssi_jws::detached_sign_unencoded_payload(
            priv_jwk.get_algorithm().expect("pass"),
            message,
            &priv_jwk,
        )
        .expect("pass");
        println!("jws: {}", jws);
        // Verify signature.
        let pub_jwk = priv_jwk.to_public();
        let jws_header = ssi_jws::detached_verify(&jws, message, &pub_jwk).expect("pass");
        println!(
            "jws header:\n{}",
            serde_json::to_string_pretty(&jws_header).unwrap()
        );
        ssi_jws::detached_verify(&jws, b"fake payload, this should fail", &pub_jwk)
            .expect_err("pass");
    }
}

#[test]
#[serial_test::serial]
fn test_microledger() {
    println!("-- TESTING MICROLEDGER ---------------------------------");
    // Create a DID and its associated Microledger
    let (mut microledger, _key_1_priv_jwk) = {
        let did = DIDWebplus::with_host("example.com").unwrap();
        let key_1_fragment = "key-1";
        let did_with_fragment = did.with_fragment(key_1_fragment).expect("pass");
        let relative_did_with_fragment = format!("#{}", key_1_fragment);
        let (verification_method, mut key_1_priv_jwk) =
            secp256k1_generate_key_pair(did_with_fragment.clone());
        let microledger = Microledger::create(RootDIDDocumentParams {
            did_webplus_with_placeholder: did.clone(),
            valid_from: chrono::Utc::now(),
            key_material: KeyMaterial {
                verification_method_v: vec![verification_method],
                authentication_fragment_v: vec![relative_did_with_fragment.clone()],
                assertion_method_fragment_v: vec![relative_did_with_fragment.clone()],
                key_agreement_fragment_v: vec![relative_did_with_fragment.clone()],
                capability_invocation_fragment_v: vec![relative_did_with_fragment.clone()],
                capability_delegation_fragment_v: vec![relative_did_with_fragment.clone()],
            },
        })
        .expect("pass");
        let did = microledger.did().clone();
        let did_with_fragment = did.with_fragment(key_1_fragment).expect("pass");
        key_1_priv_jwk.key_id = Some(did_with_fragment.into_string());
        println!("did: {}", did);
        println!("microledger:\n{:#?}", microledger);
        println!(
            "key_1_priv_jwk: {}",
            serde_json::to_string(&key_1_priv_jwk).expect("pass")
        );
        (microledger, key_1_priv_jwk)
    };

    println!("updating microledger --");
    // Update the Microledger.
    let _key_2_priv_jwk = {
        let key_2_fragment = "key-2";
        let did_with_fragment = microledger
            .did()
            .with_fragment(key_2_fragment)
            .expect("pass");
        let relative_did_with_fragment = format!("#{}", key_2_fragment);
        let (verification_method, key_2_priv_jwk) =
            ed25519_generate_key_pair(did_with_fragment.clone());
        assert_eq!(key_2_priv_jwk.key_id, Some(did_with_fragment.into_string()));
        let mut key_material = microledger.head().did_document().key_material().clone();
        key_material.verification_method_v.push(verification_method);
        key_material
            .authentication_fragment_v
            .push(relative_did_with_fragment.clone());
        key_material.assertion_method_fragment_v.clear();
        key_material
            .assertion_method_fragment_v
            .push(relative_did_with_fragment.clone());
        microledger
            .update_as_controller(NonRootDIDDocumentParams {
                valid_from: chrono::Utc::now(),
                key_material,
            })
            .expect("pass");
        println!("microledger:\n{:#?}", microledger);
        println!(
            "key_2_priv_jwk: {}",
            serde_json::to_string(&key_2_priv_jwk).expect("pass")
        );
        key_2_priv_jwk
    };

    println!(
        "root DID document:\n{}",
        serde_json::to_string_pretty(microledger.root().typed_did_document()).expect("pass")
    );
    for non_root_microledger_node in microledger.non_root_v() {
        println!(
            "non-root DID document:\n{}",
            serde_json::to_string_pretty(&non_root_microledger_node.typed_did_document())
                .expect("pass")
        );
    }
}

// Convenience function for creating a test ed25519 public key.
#[allow(unused)]
fn public_key_jwk_example_ed25519(kid_o: Option<DIDWebplusWithFragment>) -> PublicKeyJWK {
    PublicKeyJWK {
        kid_o,
        public_key_params: public_key_params_okp_example_ed25519().into(),
    }
}

// Convenience function for creating a test PublicKeyJWK.  The "kid" field
// will be left as the empty String, which is ok because various VerificationMethod
// constructor(s) will populate it automatically.
#[allow(unused)]
fn public_key_jwk_example_secp256k1(kid_o: Option<DIDWebplusWithFragment>) -> PublicKeyJWK {
    PublicKeyJWK {
        kid_o,
        public_key_params: public_key_params_ec_example_secp256k1().into(),
    }
}

fn public_key_params_ec_example_secp256k1() -> PublicKeyParamsEC {
    PublicKeyParamsEC {
        crv: "secp256k1".into(),
        x: "1pKM4zhV7FSGcfsrwDNA7pkYBxCEeLhxZuLLSedk2c0".into(),
        y: "3jvUoto-2AemhXVgXabEa7n97jKEmZu8RDiBXFPML4E".into(),
    }
}

fn public_key_params_okp_example_ed25519() -> PublicKeyParamsOKP {
    PublicKeyParamsOKP {
        crv: "ed25519".into(),
        x: "WxbNdA24kW64p8eg7FMeW1hYYL72FYUcpPz5wDJ4s7N".into(),
    }
}

#[allow(unused)]
fn public_key_jwk_from_ssi_jwk(ssi_jwk: &ssi_jwk::JWK) -> Result<PublicKeyJWK, &'static str> {
    Ok(PublicKeyJWK {
        kid_o: None,
        public_key_params: public_key_params_from_ssi_jwk(ssi_jwk)?,
    })
}

// TODO: If this were to make it into did_webplus crate, then this should be a TryFrom<&ssi_jwk::ECParams>
fn public_key_params_ec_from_ssi_ec_params(
    ssi_ec_params: &ssi_jwk::ECParams,
) -> Result<PublicKeyParamsEC, &'static str> {
    if ssi_ec_params.curve.is_none() {
        return Err("Expected curve field in EC params definition");
    }
    let crv = ssi_ec_params.curve.as_ref().unwrap();
    if crv.is_empty() {
        return Err("Expected nonempty curve field in EC params definition");
    }
    Ok(PublicKeyParamsEC {
        crv: crv.clone(),
        x: String::from(
            ssi_ec_params
                .x_coordinate
                .as_ref()
                .expect("expected x coordinate of EC key"),
        ),
        y: String::from(
            ssi_ec_params
                .y_coordinate
                .as_ref()
                .expect("expected x coordinate of EC key"),
        ),
    })
}

// TODO: If this were to make it into did_webplus crate, then this should be a TryFrom<&ssi_jwk::OctetParams>
fn public_key_params_okp_from_ssi_okp_params(
    ssi_okp_params: &ssi_jwk::OctetParams,
) -> Result<PublicKeyParamsOKP, &'static str> {
    if ssi_okp_params.curve.is_empty() {
        return Err("Expected nonempty curve field in OKP params definition");
    }
    let crv = ssi_okp_params.curve.clone();
    Ok(PublicKeyParamsOKP {
        crv,
        x: String::from(&ssi_okp_params.public_key),
    })
}

// TODO: If this were to make it into did_webplus crate, then this should be a TryFrom<&ssi_jwk::JWK>
fn public_key_params_from_ssi_jwk(ssi_jwk: &ssi_jwk::JWK) -> Result<PublicKeyParams, &'static str> {
    match &ssi_jwk.params {
        ssi_jwk::Params::OKP(ssi_okp_params) => {
            Ok(public_key_params_okp_from_ssi_okp_params(&ssi_okp_params)?.into())
        }
        ssi_jwk::Params::EC(ssi_ec_params) => {
            Ok(public_key_params_ec_from_ssi_ec_params(&ssi_ec_params)?.into())
        }
        _ => Err("Only EC keys (e.g. 'secp256k1', 'P-256', 'P-384', 'P-521') and OKP keys (e.g. 'ed25519') are supported"),
    }
}

#[allow(unused)]
fn ed25519_generate_key_pair(
    did_webplus_with_fragment: DIDWebplusWithFragment,
) -> (VerificationMethod, ssi_jwk::JWK) {
    let mut priv_jwk = ssi_jwk::JWK::generate_ed25519().unwrap();
    priv_jwk.key_id = Some(did_webplus_with_fragment.to_string());
    println!(
        "priv JWK: {}",
        serde_json::to_string_pretty(&priv_jwk).unwrap()
    );
    let public_key_params = public_key_params_from_ssi_jwk(&priv_jwk.to_public()).expect("pass");
    let verification_method =
        VerificationMethod::json_web_key_2020(did_webplus_with_fragment, public_key_params);
    (verification_method, priv_jwk)
}

fn secp256k1_generate_key_pair(
    did_webplus_with_fragment: DIDWebplusWithFragment,
) -> (VerificationMethod, ssi_jwk::JWK) {
    let mut priv_jwk = ssi_jwk::JWK::generate_secp256k1().unwrap();
    priv_jwk.key_id = Some(did_webplus_with_fragment.to_string());
    println!(
        "priv JWK: {}",
        serde_json::to_string_pretty(&priv_jwk).unwrap()
    );
    let public_key_params = public_key_params_from_ssi_jwk(&priv_jwk.to_public()).expect("pass");
    let verification_method =
        VerificationMethod::json_web_key_2020(did_webplus_with_fragment, public_key_params);
    (verification_method, priv_jwk)
}
