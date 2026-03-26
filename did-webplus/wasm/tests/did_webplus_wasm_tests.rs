#![cfg(target_arch = "wasm32")]

use std::{ops::Deref, sync::Arc};

use wasm_bindgen_test::wasm_bindgen_test;

// TEMP -- disable vjson tests for now.

/*
#[wasm_bindgen_test]
#[allow(unused)]
async fn test_vjson_self_hash_and_verify() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Debug));

    let vjson_store = did_webplus_wasm::VJSONStore::new_mock()
        .await
        .expect("pass");
    let vjson_resolver = vjson_store.as_resolver();
    // There are no signatures to verify, so we can use an empty VerifierResolver.
    let verifier_resolver = did_webplus_wasm::VerifierResolver::new_empty();

    let vjson_string = did_webplus_wasm::vjson_self_hash(
        r#"{"blah":123, "$id":"vjson:///"}"#.to_string(),
        &vjson_resolver,
    )
    .await
    .expect("pass");

    tracing::debug!("self-hashed VJSON: {}", vjson_string);
    assert_eq!(
        vjson_string.as_str(),
        r#"{"$id":"vjson:///Eapp9Rz4xD0CT7VnplnK4nAb--YlkfAaq0PYPRV43XZY","$schema":"vjson:///EnD4KcLMLmGSjEliVPgBdMsEC2B_brlSXPV2pu7W90Xc","blah":123,"selfHash":"Eapp9Rz4xD0CT7VnplnK4nAb--YlkfAaq0PYPRV43XZY"}"#
    );

    let x = did_webplus_wasm::vjson_verify(vjson_string, &vjson_resolver, &verifier_resolver)
        .await
        .expect("pass");
}

#[wasm_bindgen_test]
#[allow(unused)]
async fn test_vjson_sign_and_verify() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Debug));

    let vjson_store = did_webplus_wasm::VJSONStore::new_mock()
        .await
        .expect("pass");
    let vjson_resolver = vjson_store.as_resolver();
    // Signatures will be from did:key keys only.
    let verifier_resolver = did_webplus_wasm::VerifierResolver::new_with_did_key();

    // Generate a private key to sign with.
    let signer = did_webplus_wasm::Signer::did_key_generate(did_webplus_wasm::KeyType::Ed25519)
        .expect("pass");

    let vjson_string = did_webplus_wasm::vjson_sign_and_self_hash(
        r#"{"blah":123, "$id":"vjson:///"}"#.to_string(),
        &signer,
        &vjson_resolver,
    )
    .await
    .expect("pass");

    tracing::debug!("signed VJSON: {}", vjson_string);

    let x = did_webplus_wasm::vjson_verify(vjson_string, &vjson_resolver, &verifier_resolver)
        .await
        .expect("pass");
}
*/

#[wasm_bindgen_test]
#[allow(unused)]
async fn test_software_wallet_indexeddb() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Debug));

    tracing::debug!("test_software_wallet_indexeddb");
    // Use a unique DB name per run so headful runs don't see stale IndexedDB from previous runs
    // (which can cause "Unknown base code: D" when deserializing corrupted/stale multibase fields).
    let db_name = format!("test_software_wallet_indexeddb_{}", uuid::Uuid::new_v4());

    let wallet = did_webplus_wasm::Wallet::create(db_name, None, None)
        .await
        .expect("pass");
    tracing::debug!("wallet successfully created");

    let mb_hash_function = did_webplus_wasm::MBHashFunction::new(
        did_webplus_wasm::Base::Base64Url,
        did_webplus_wasm::HashFunction::Blake3,
    );

    let mut http_scheme_override = did_webplus_wasm::HTTPSchemeOverride::new();
    http_scheme_override
        .add_override("vdr.did-webplus-wasm.test".to_string(), "http".to_string())
        .expect("pass");
    let mut http_options = did_webplus_wasm::HTTPOptions::new();
    http_options.set_http_scheme_override(http_scheme_override);

    let controlled_did = wallet
        .create_did(
            did_webplus_wasm::CreateDIDParameters::new(
                "https://vdr.did-webplus-wasm.test:8085".to_string(),
                mb_hash_function.clone(),
                Some(mb_hash_function.clone()),
            ),
            Some(http_options.clone()),
        )
        .await
        .expect("pass");
    tracing::debug!("controlled_did: {:?}", controlled_did);

    let did = did_webplus_core::DIDFullyQualifiedStr::new_ref(&controlled_did)
        .expect("pass")
        .did()
        .to_owned();
    tracing::debug!("did: {:?}", did);

    // Get a WalletBasedSigner for signing operations.
    let wallet_based_signer = wallet
        .new_wallet_based_signer(
            did.to_string(),
            "assertionMethod".to_string(),
            None,
            Some(http_options.clone()),
        )
        .await
        .expect("pass");

    // Defines the shape of our custom claims.
    #[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
    pub struct Claims {
        name: String,
        email: String,
    }

    // Create JWT claims from our custom ("private") claims.
    let claims = ssi_claims::JWTClaims::from_private_claims(Claims {
        name: "Grunty McParty".to_owned(),
        email: "g@mc-p.org".to_owned(),
    });

    // TEMP HACK -- use an in-memory DID doc store for now.
    let did_resolver_a = {
        let doc_storage_mock = did_webplus_doc_storage_mock::DIDDocStorageMock::new();
        let doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(doc_storage_mock));
        let http_scheme_override = did_webplus_core::HTTPSchemeOverride::new()
            .with_override("vdr.did-webplus-wasm.test".to_string(), "http")
            .expect("pass");
        let http_options = did_webplus_core::HTTPOptions {
            http_scheme_override,
            ..Default::default()
        };
        let did_resolver_full =
            did_webplus_resolver::DIDResolverFull::new(doc_store, None, Some(http_options))
                .expect("pass");
        Arc::new(did_resolver_full)
    };
    let did_resolver = did_webplus_wasm::DIDResolver::new(did_resolver_a.clone());

    // TODO: JWS sign and verify.

    // Sign and verify a JWT using did_webplus_ssi
    {
        // Sign the claims.
        let jwt = did_webplus_ssi::sign_jwt(&claims, wallet_based_signer.deref())
            .await
            .expect("signature failed");
        tracing::info!("jwt: {}", jwt);
        let jwt_string = jwt.to_string();

        // Verify the JWT.
        did_webplus_ssi::verify_jwt(&jwt_string, did_resolver_a.clone())
            .await
            .expect("verification failed");
    }

    // Sign and verify a JWT using jwt_sign and jwt_verify
    let jwt_string = {
        // Sign the claims.
        let claims_jsvalue = serde_wasm_bindgen::to_value(&claims).expect("pass");
        let jwt_string = did_webplus_wasm::jwt_sign(claims_jsvalue, &wallet_based_signer)
            .await
            .expect("signature failed");
        tracing::info!("jwt_string: {}", jwt_string);

        // Verify the JWT.
        let jwt_verify_r = did_webplus_wasm::jwt_verify(jwt_string.clone(), &did_resolver).await;
        tracing::debug!("jwt_verify_r: {:?}", jwt_verify_r);
        assert!(jwt_verify_r.is_ok());

        jwt_string
    };

    let unsigned_credential = {
        let issuance_date = time::OffsetDateTime::now_utc();
        let expiration_date = issuance_date + time::Duration::days(365);
        did_webplus_ssi::new_unsigned_credential(
            None,
            "https://example.org/#CredentialId",
            issuance_date,
            expiration_date,
            serde_json::json!({
                "id": "https://example.org/#CredentialSubjectId",
                "https://example.org/#name": "Grunty McParty",
                "https://example.org/#email": "g@mc-p.org",
            }),
        )
    };
    let unsigned_credential_jsvalue = {
        let issuance_date = js_sys::Date::new_0();
        let expiration_date =
            js_sys::Date::new_with_year_month_day_hr_min_sec_milli(2039, 1, 1, 0, 0, 0, 0);
        did_webplus_wasm::new_unsigned_credential(
            None,
            "https://example.org/#CredentialId".to_string(),
            issuance_date,
            expiration_date,
            serde_wasm_bindgen::to_value(&serde_json::json!({
                "id": "https://example.org/#CredentialSubjectId",
                "https://example.org/#name": "Grunty McParty",
                "https://example.org/#email": "g@mc-p.org",
            }))
            .expect("pass"),
        )
        .expect("pass")
    };

    // Sign and verify an LDP-formatted VC using did_webplus_ssi
    let vc_ldp = {
        // Sign the VC.
        let vc_ldp = did_webplus_ssi::issue_vc_ldp(
            unsigned_credential.clone(),
            wallet_based_signer.deref(),
            did_resolver_a.clone(),
        )
        .await
        .expect("signature failed");
        tracing::info!("vc_ldp: {:?}", vc_ldp);
        vc_ldp
    };
    // Verify the VC.
    {
        let vc_ldp_verify_r = did_webplus_ssi::verify_vc_ldp(&vc_ldp, did_resolver_a.clone()).await;
        tracing::debug!("vc_ldp_verify_r: {:?}", vc_ldp_verify_r);
        assert!(vc_ldp_verify_r.is_ok());
        let vc_ldp_verify_proof_r = vc_ldp_verify_r.unwrap();
        tracing::debug!("vc_ldp_verify_proof_r: {:?}", vc_ldp_verify_proof_r);
        assert!(vc_ldp_verify_proof_r.is_ok());
    }

    // Sign and verify an LDP-formatted VC using did_webplus_wasm
    let vc_ldp_jsvalue = {
        let vc_ldp_jsvalue = did_webplus_wasm::issue_vc_ldp(
            unsigned_credential_jsvalue,
            &wallet_based_signer,
            &did_resolver,
        )
        .await
        .expect("signature failed");
        tracing::info!("vc_ldp_jsvalue: {:?}", vc_ldp_jsvalue);
        {
            let vc_ldp =
                serde_wasm_bindgen::from_value::<serde_json::Value>(vc_ldp_jsvalue.clone())
                    .expect("pass");
            tracing::debug!("vc_ldp as JSON: {}", vc_ldp);
        }

        // Verify the VC.
        did_webplus_wasm::verify_vc_ldp(vc_ldp_jsvalue.clone(), &did_resolver)
            .await
            .expect("verification failed");
        vc_ldp_jsvalue
    };

    // Sign and verify a JWT-formatted VC using did_webplus_ssi
    {
        // Sign the VC.
        let vc_jwt =
            did_webplus_ssi::issue_vc_jwt(unsigned_credential.clone(), &wallet_based_signer)
                .await
                .expect("signature failed");
        tracing::info!("vc_jwt: {:?}", vc_jwt);

        // Verify the VC.
        did_webplus_ssi::verify_vc_jwt(&vc_jwt, did_resolver_a.clone())
            .await
            .expect("verification failed");
    }

    // Sign and verify a JWT-formatted VC using did_webplus_wasm
    let vc_jwt = {
        let unsigned_credential_jsvalue =
            serde_wasm_bindgen::to_value(&unsigned_credential).expect("pass");
        let vc_jwt =
            did_webplus_wasm::issue_vc_jwt(unsigned_credential_jsvalue, &wallet_based_signer)
                .await
                .expect("signature failed");
        tracing::info!("vc_jwt: {:?}", vc_jwt);

        // Verify the VC.
        did_webplus_wasm::verify_vc_jwt(vc_jwt.clone(), &did_resolver)
            .await
            .expect("verification failed");
        vc_jwt
    };

    // Now we'll present each VC as both types of VP -- LDP and JWT formats.

    // LDP format VP of LDP-formatted VC
    let vp_ldp_of_vc_ldp = {
        // Issue the VP.
        let unsigned_presentation_jsvalue = did_webplus_wasm::new_unsigned_presentation(
            None,
            "https://example.org/#PresentationId".to_string(),
            None,
            None,
            Some(vec![vc_ldp_jsvalue.clone()]),
        )
        .expect("pass");
        let vp_ldp_of_vc_ldp = did_webplus_wasm::issue_vp_ldp(
            unsigned_presentation_jsvalue,
            did_webplus_wasm::IssueVPParameters::new(Some("1234567890".to_string()), None, None),
            &wallet_based_signer,
            &did_resolver,
        )
        .await
        .expect("signature failed");
        {
            let vp = serde_wasm_bindgen::from_value::<serde_json::Value>(vp_ldp_of_vc_ldp.clone())
                .expect("pass");
            tracing::info!("vp_ldp_of_vc_ldp: {}", vp);
        }

        // Verify the VP.
        did_webplus_wasm::verify_vp_ldp(vp_ldp_of_vc_ldp.clone(), &did_resolver)
            .await
            .expect("verification failed");

        vp_ldp_of_vc_ldp
    };

    // JWT format VP of LDP-formatted VC
    let vp_jwt_of_vc_ldp = {
        // Issue the VP.
        let unsigned_presentation_jsvalue = did_webplus_wasm::new_unsigned_presentation(
            None,
            "https://example.org/#PresentationId".to_string(),
            Some(js_sys::Date::new_0()),
            Some(js_sys::Date::new_with_year_month_day_hr_min_sec_milli(
                2039, 1, 1, 0, 0, 0, 0,
            )),
            Some(vec![vc_ldp_jsvalue.clone()]),
        )
        .expect("pass");
        let vp_jwt_of_vc_ldp = did_webplus_wasm::issue_vp_jwt(
            unsigned_presentation_jsvalue,
            did_webplus_wasm::IssueVPParameters::new(Some("1234567890".to_string()), None, None),
            &wallet_based_signer,
        )
        .await
        .expect("signature failed");
        tracing::info!("vp_jwt_of_vc_ldp: {}", vp_jwt_of_vc_ldp);

        // Verify the VP.
        did_webplus_wasm::verify_vp_jwt(vp_jwt_of_vc_ldp.clone(), &did_resolver)
            .await
            .expect("verification failed");
        vp_jwt_of_vc_ldp
    };

    // LDP format VP of JWT-formatted VC
    let vp_ldp_of_vc_jwt = {
        // Issue the VP.
        let unsigned_presentation_jsvalue = did_webplus_wasm::new_unsigned_presentation(
            None,
            "https://example.org/#PresentationId".to_string(),
            None,
            None,
            Some(vec![serde_wasm_bindgen::to_value(&vc_jwt).expect("pass")]),
        )
        .expect("pass");
        let vp_ldp_of_vc_jwt = did_webplus_wasm::issue_vp_ldp(
            unsigned_presentation_jsvalue,
            did_webplus_wasm::IssueVPParameters::new(Some("1234567890".to_string()), None, None),
            &wallet_based_signer,
            &did_resolver,
        )
        .await
        .expect("signature failed");
        {
            let vp = serde_wasm_bindgen::from_value::<serde_json::Value>(vp_ldp_of_vc_jwt.clone())
                .expect("pass");
            tracing::info!("vp_ldp_of_vc_jwt: {}", vp);
        }

        // Verify the VP.
        did_webplus_wasm::verify_vp_ldp(vp_ldp_of_vc_jwt.clone(), &did_resolver)
            .await
            .expect("verification failed");
        vp_ldp_of_vc_jwt
    };

    // JWT format VP of JWT-formatted VC
    let vp_jwt_of_vc_jwt = {
        // Issue the VP.
        let unsigned_presentation_jsvalue = did_webplus_wasm::new_unsigned_presentation(
            None,
            "https://example.org/#PresentationId".to_string(),
            Some(js_sys::Date::new_0()),
            Some(js_sys::Date::new_with_year_month_day_hr_min_sec_milli(
                2039, 1, 1, 0, 0, 0, 0,
            )),
            Some(vec![serde_wasm_bindgen::to_value(&vc_jwt).expect("pass")]),
        )
        .expect("pass");
        let vp_jwt_of_vc_jwt = did_webplus_wasm::issue_vp_jwt(
            unsigned_presentation_jsvalue,
            did_webplus_wasm::IssueVPParameters::new(Some("1234567890".to_string()), None, None),
            &wallet_based_signer,
        )
        .await
        .expect("signature failed");
        tracing::info!("vp_jwt_of_vc_jwt: {}", vp_jwt_of_vc_jwt);

        // Verify the VP.
        did_webplus_wasm::verify_vp_jwt(vp_jwt_of_vc_jwt.clone(), &did_resolver)
            .await
            .expect("verification failed");
        vp_jwt_of_vc_jwt
    };

    let controlled_did = wallet
        .update_did(
            did_webplus_wasm::UpdateDIDParameters::new(
                did_webplus_wasm::DID::from(did.clone()),
                None,
                Some(mb_hash_function.clone()),
            ),
            Some(http_options.clone()),
        )
        .await
        .expect("pass");

    // Verify all the stuff again after updating the DID.
    {
        // Verify the JWT.
        did_webplus_wasm::jwt_verify(jwt_string, &did_resolver)
            .await
            .expect("pass");

        // Verify the VC in each format.
        did_webplus_wasm::verify_vc_ldp(vc_ldp_jsvalue, &did_resolver)
            .await
            .expect("verification failed");
        did_webplus_wasm::verify_vc_jwt(vc_jwt, &did_resolver)
            .await
            .expect("verification failed");

        // Verify the VP in each format.
        did_webplus_wasm::verify_vp_ldp(vp_ldp_of_vc_ldp, &did_resolver)
            .await
            .expect("verification failed");
        did_webplus_wasm::verify_vp_jwt(vp_jwt_of_vc_ldp, &did_resolver)
            .await
            .expect("verification failed");
        did_webplus_wasm::verify_vp_ldp(vp_ldp_of_vc_jwt, &did_resolver)
            .await
            .expect("verification failed");
        did_webplus_wasm::verify_vp_jwt(vp_jwt_of_vc_jwt, &did_resolver)
            .await
            .expect("verification failed");
    }

    let controlled_did = wallet
        .deactivate_did(
            did_webplus_wasm::DeactivateDIDParameters::new(
                did_webplus_wasm::DID::from(did.clone()),
                Some(mb_hash_function.clone()),
            ),
            Some(http_options.clone()),
        )
        .await
        .expect("pass");
}
