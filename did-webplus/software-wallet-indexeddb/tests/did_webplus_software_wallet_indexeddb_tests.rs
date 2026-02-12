#![cfg(target_arch = "wasm32")]

use did_webplus_core::KeyPurpose;
use did_webplus_wallet_store::LocallyControlledVerificationMethodFilter;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
#[allow(unused)]
async fn test_software_wallet_indexeddb_basic() {
    console_error_panic_hook::set_once();
    wasm_tracing::set_as_global_default();

    tracing::debug!("Starting test_software_wallet_indexeddb_basic");

    let software_wallet_indexeddb =
        did_webplus_software_wallet_indexeddb::SoftwareWalletIndexedDB::create(
            "test_software_wallet_indexeddb_basic".to_string(),
            1,
            Some("test_software_wallet_indexeddb_basic Wallet #0".to_string()),
            None,
        )
        .await
        .expect("pass");

    tracing::debug!("software_wallet_indexeddb: {:?}", software_wallet_indexeddb);

    let mb_hash_function = selfhash::MBHashFunction::blake3(mbx::Base::Base64Url);

    let http_headers_for = did_webplus_core::HTTPHeadersFor::new();
    let http_scheme_override = did_webplus_core::HTTPSchemeOverride::new()
        .with_override("vdr.did-webplus-wasm.test".to_string(), "http")
        .expect("pass");
    let http_options = did_webplus_core::HTTPOptions {
        http_headers_for,
        http_scheme_override,
    };

    use did_webplus_wallet::Wallet;

    // Verify no locally controlled verification methods before create_did.
    let locally_controlled_verification_methods_before_create_v = software_wallet_indexeddb
        .get_locally_controlled_verification_methods(
            &LocallyControlledVerificationMethodFilter::default(),
        )
        .await
        .expect("pass");
    assert!(
        locally_controlled_verification_methods_before_create_v.is_empty(),
        "expected no locally controlled verification methods before create_did, got {}",
        locally_controlled_verification_methods_before_create_v.len()
    );

    let controlled_did = software_wallet_indexeddb
        .create_did(
            did_webplus_wallet::CreateDIDParameters {
                vdr_did_create_endpoint: "https://vdr.did-webplus-wasm.test:8085",
                mb_hash_function_for_did: &mb_hash_function,
                mb_hash_function_for_update_key_o: Some(&mb_hash_function),
            },
            Some(&http_options),
        )
        .await
        .expect("pass");
    tracing::debug!("controlled_did: {:?}", controlled_did);
    let did = controlled_did.did();
    tracing::debug!("did: {:?}", did);

    // Verify one set of locally controlled verification methods after create_did (version 0).
    let locally_controlled_verification_methods_after_create_v = software_wallet_indexeddb
        .get_locally_controlled_verification_methods(&LocallyControlledVerificationMethodFilter {
            did_o: Some(did.to_owned()),
            version_id_o: Some(0),
            key_purpose_o: None,
            key_id_o: None,
            result_limit_o: None,
        })
        .await
        .expect("pass");
    assert!(
        !locally_controlled_verification_methods_after_create_v.is_empty(),
        "expected at least one locally controlled verification method after create_did"
    );
    let expected_count = KeyPurpose::VERIFICATION_METHOD_VARIANTS.len();
    assert_eq!(
        locally_controlled_verification_methods_after_create_v.len(),
        expected_count,
        "expected {} verification methods after create_did, got {}",
        expected_count,
        locally_controlled_verification_methods_after_create_v.len()
    );
    let pub_keys_after_create: std::collections::HashSet<_> =
        locally_controlled_verification_methods_after_create_v
            .iter()
            .map(|(record, _)| record.pub_key.to_string())
            .collect();

    let controlled_did = software_wallet_indexeddb
        .update_did(
            did_webplus_wallet::UpdateDIDParameters {
                did: &did,
                change_mb_hash_function_for_self_hash_o: None,
                mb_hash_function_for_update_key_o: Some(&mb_hash_function),
            },
            Some(&http_options),
        )
        .await
        .expect("pass");
    tracing::debug!("controlled_did: {:?}", controlled_did);

    // Verify the old set (version 0) is retired and a new set (version 1) is present.
    let locally_controlled_verification_methods_version_0_after_update_v =
        software_wallet_indexeddb
            .get_locally_controlled_verification_methods(
                &LocallyControlledVerificationMethodFilter {
                    did_o: Some(did.to_owned()),
                    version_id_o: Some(0),
                    key_purpose_o: None,
                    key_id_o: None,
                    result_limit_o: None,
                },
            )
            .await
            .expect("pass");
    assert!(
        locally_controlled_verification_methods_version_0_after_update_v.is_empty(),
        "expected no locally controlled verification methods for version 0 after update_did (old keys should be retired), got {}",
        locally_controlled_verification_methods_version_0_after_update_v.len()
    );

    let locally_controlled_verification_methods_version_1_after_update_v =
        software_wallet_indexeddb
            .get_locally_controlled_verification_methods(
                &LocallyControlledVerificationMethodFilter {
                    did_o: Some(did.to_owned()),
                    version_id_o: Some(1),
                    key_purpose_o: None,
                    key_id_o: None,
                    result_limit_o: None,
                },
            )
            .await
            .expect("pass");
    assert_eq!(
        locally_controlled_verification_methods_version_1_after_update_v.len(),
        expected_count,
        "expected {} verification methods for version 1 after update_did, got {}",
        expected_count,
        locally_controlled_verification_methods_version_1_after_update_v.len()
    );
    let pub_keys_after_update: std::collections::HashSet<_> =
        locally_controlled_verification_methods_version_1_after_update_v
            .iter()
            .map(|(record, _)| record.pub_key.to_string())
            .collect();
    assert!(
        pub_keys_after_create.is_disjoint(&pub_keys_after_update),
        "expected new verification methods after update_did to have different pub_keys than the retired set"
    );
}
