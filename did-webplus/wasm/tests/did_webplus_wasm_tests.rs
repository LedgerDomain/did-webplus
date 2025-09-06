#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::wasm_bindgen_test;

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
    let signer =
        did_webplus_wasm::Signer::did_key_generate(selfsign::KeyType::Ed25519).expect("pass");

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

#[wasm_bindgen_test]
#[allow(unused)]
async fn test_software_wallet_indexeddb() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Debug));

    tracing::debug!("test_software_wallet_indexeddb");
    let db_name = "test_software_wallet_indexeddb";

    let wallet = did_webplus_wasm::Wallet::create(db_name.to_string(), None)
        .await
        .expect("pass");
    tracing::debug!("wallet successfully created");

    let controlled_did = wallet
        .create_did("http://vdr.did-webplus-wasm.test:8085".to_string())
        .await
        .expect("pass");
    tracing::debug!("controlled_did: {:?}", controlled_did);

    let did = did_webplus_core::DIDFullyQualifiedStr::new_ref(&controlled_did)
        .expect("pass")
        .did()
        .to_owned();
    tracing::debug!("did: {:?}", did);

    let controlled_did = wallet
        .update_did(did.to_string(), "http".to_string())
        .await
        .expect("pass");
}
