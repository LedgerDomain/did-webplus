use std::collections::HashMap;

use did_webplus::{
    said_placeholder, said_placeholder_for_uri, DIDDocument, DIDWebplus, DIDWebplusWithFragment,
    PublicKeyBase58, PublicKeyJWK, VerificationMethod, SAID_HASH_FUNCTION_CODE,
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
            VerificationMethod::ecdsa_secp256k1_verification_key_2019(
                did.with_fragment("key-1").expect("pass"),
                public_key_jwk_example_with_empty_kid_field(),
            ),
            VerificationMethod::ed25519_verification_key_2018(
                did.with_fragment("key-2").expect("pass"),
                public_key_base58_example(),
            ),
        ],
        authentication_fragment_v: vec!["#key-1".into()],
        assertion_fragment_v: vec!["#key-2".into()],
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

#[test]
#[serial_test::serial]
fn test_did_document_verification() {
    let did = DIDWebplus::with_host("example.com").unwrap();
    let mut did_document_0 = DIDDocument {
        id: did.clone(),
        prev_did_document_hash_o: None,
        valid_from: chrono::Utc::now(),
        version_id: 0,
        verification_method_v: vec![VerificationMethod::ecdsa_secp256k1_verification_key_2019(
            did.with_fragment("key-1").expect("pass"),
            public_key_jwk_example_with_empty_kid_field(),
        )],
        authentication_fragment_v: vec!["#key-1".into()],
        assertion_fragment_v: vec!["#key-1".into()],
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
            VerificationMethod::ecdsa_secp256k1_verification_key_2019(
                did.with_fragment("key-1").expect("pass"),
                public_key_jwk_example_with_empty_kid_field(),
            ),
            VerificationMethod::ed25519_verification_key_2018(
                did.with_fragment("key-2").expect("pass"),
                public_key_base58_example(),
            ),
        ],
        authentication_fragment_v: vec!["#key-1".into()],
        assertion_fragment_v: vec!["#key-2".into()],
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
fn test_signature_generation() {
    let did = DIDWebplus::with_host("example.com").unwrap();
    let fragment = "key-1";
    let did_with_fragment = did.with_fragment(fragment).expect("pass");
    let relative_did_with_fragment = format!("#{}", fragment);
    let (verification_method, mut priv_jwk) = secp256k1_generate_key_pair(did_with_fragment);
    let mut did_document_0 = DIDDocument {
        id: did.clone(),
        prev_did_document_hash_o: None,
        valid_from: chrono::Utc::now(),
        version_id: 0,
        verification_method_v: vec![verification_method],
        authentication_fragment_v: vec![relative_did_with_fragment.clone()],
        assertion_fragment_v: vec![relative_did_with_fragment.clone()],
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
    let jws =
        ssi_jws::detached_sign_unencoded_payload(ssi_jwk::Algorithm::ES256K, message, &priv_jwk)
            .expect("pass");
    println!("jws: {}", jws);
    // Verify signature.
    let pub_jwk = priv_jwk.to_public();
    let jws_header = ssi_jws::detached_verify(&jws, message, &pub_jwk).expect("pass");
    println!(
        "jws header:\n{}",
        serde_json::to_string_pretty(&jws_header).unwrap()
    );
    ssi_jws::detached_verify(&jws, b"fake payload, this should fail", &pub_jwk).expect_err("pass");
}

// Convenience function for creating a test PublicKeyBase58
fn public_key_base58_example() -> PublicKeyBase58 {
    PublicKeyBase58::try_from("WxbNdA24kW64p8eg7FMeW1hYYL72FYUcpPz5wDJ4s7N".to_string()).unwrap()
}

// Convenience function for creating a test PublicKeyJWK.  The "kid" field
// will be left as the empty String, which is ok because various VerificationMethod
// constructor(s) will populate it automatically.
fn public_key_jwk_example_with_empty_kid_field() -> PublicKeyJWK {
    PublicKeyJWK {
        kid_o: None,
        kty: "EC".into(),
        crv: "secp256k1".into(),
        x: "1pKM4zhV7FSGcfsrwDNA7pkYBxCEeLhxZuLLSedk2c0".into(),
        y: "3jvUoto-2AemhXVgXabEa7n97jKEmZu8RDiBXFPML4E".into(),
    }
}

// Convenience function for creating a test PublicKeyJWK.  You must supply
// the DIDWebplusWithFragment, because that is used to populate the "kid" field.
#[allow(unused)]
fn public_key_jwk_example_with_kid_field(
    did_webplus_with_fragment: DIDWebplusWithFragment,
) -> PublicKeyJWK {
    PublicKeyJWK {
        kid_o: Some(did_webplus_with_fragment),
        kty: "EC".into(),
        crv: "secp256k1".into(),
        x: "1pKM4zhV7FSGcfsrwDNA7pkYBxCEeLhxZuLLSedk2c0".into(),
        y: "3jvUoto-2AemhXVgXabEa7n97jKEmZu8RDiBXFPML4E".into(),
    }
}

// impl TryFrom<ssi_jwk::JWK> for PublicKeyJWK {
//     type Error = &'static str;
//     fn try_from(jwk: ssi_jwk::JWK) -> Result<Self, Self::Error> {
//         if let ssi_jwk::Params::EC(ec_params) = jwk.params {
//             if ec_params.curve.is_none() {
//                 return Err("Expected nonempty curve field in EC params definition");
//             }
//             let crv = ec_params.curve.unwrap();
//             Ok(PublicKeyJWK {
//                 kid_o: None,
//                 kty: "EC".to_string(),
//                 crv,
//                 x: ec_params.x,
//                 y: ec_params.y,
//             })
//         } else {
//             return Err("Only EC keys are supported");
//         }
//     }
// }
fn public_key_jwk_from_ssi_jwk(jwk: &ssi_jwk::JWK) -> Result<PublicKeyJWK, &'static str> {
    if let ssi_jwk::Params::EC(ec_params) = &jwk.params {
        if ec_params.curve.is_none() {
            return Err("Expected nonempty curve field in EC params definition");
        }
        let crv = ec_params.curve.as_ref().unwrap().clone();
        Ok(PublicKeyJWK {
            kid_o: None,
            kty: "EC".to_string(),
            crv,
            x: String::from(
                ec_params
                    .x_coordinate
                    .as_ref()
                    .expect("expected x coordinate of EC key"),
            ),
            y: String::from(
                ec_params
                    .y_coordinate
                    .as_ref()
                    .expect("expected x coordinate of EC key"),
            ),
        })
    } else {
        return Err("Only EC keys are supported");
    }
}

fn secp256k1_generate_key_pair(
    did_webplus_with_fragment: DIDWebplusWithFragment,
) -> (VerificationMethod, ssi_jwk::JWK) {
    let priv_jwk = ssi_jwk::JWK::generate_secp256k1().unwrap();
    println!(
        "priv JWK: {}",
        serde_json::to_string_pretty(&priv_jwk).unwrap()
    );
    let pub_jwk = public_key_jwk_from_ssi_jwk(&priv_jwk.to_public()).expect("pass");
    let verification_method =
        VerificationMethod::json_web_key_2020(did_webplus_with_fragment, pub_jwk);
    (verification_method, priv_jwk)
}
