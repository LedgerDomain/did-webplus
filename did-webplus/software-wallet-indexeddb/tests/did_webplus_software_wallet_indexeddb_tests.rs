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
        )
        .await
        .expect("pass");

    tracing::debug!("software_wallet_indexeddb: {:?}", software_wallet_indexeddb);

    use did_webplus_wallet::Wallet;
    let controlled_did = software_wallet_indexeddb
        .create_did("http://localhost:12321")
        .await
        .expect("pass");
    tracing::debug!("controlled_did: {:?}", controlled_did);
    let did = controlled_did.did();
    tracing::debug!("did: {:?}", did);

    let controlled_did = software_wallet_indexeddb
        .update_did(&did, "http")
        .await
        .expect("pass");
    tracing::debug!("controlled_did: {:?}", controlled_did);
}
