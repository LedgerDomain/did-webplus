#![cfg(target_arch = "wasm32")]

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
}
