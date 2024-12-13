use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn test_blah() {
    console_error_panic_hook::set_once();

    // let _signer = did_webplus_wasm::Signer::did_key_generate(selfsign::KeyType::Ed25519).unwrap();
    assert!(true);
}
