use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
#[allow(unused)]
async fn test_vjson() {
    console_error_panic_hook::set_once();

    let vjson_store = did_webplus_wasm::VJSONStore::new_mock()
        .await
        .expect("pass");

    let json_string = r#"{"blah":123, "$id":"vjson:///"}"#.to_string();
    let vjson_string = did_webplus_wasm::vjson_self_hash(json_string, &vjson_store)
        .await
        .expect("pass");

    assert_eq!(
        vjson_string.as_str(),
        r#"{"$id":"vjson:///Eapp9Rz4xD0CT7VnplnK4nAb--YlkfAaq0PYPRV43XZY","$schema":"vjson:///EnD4KcLMLmGSjEliVPgBdMsEC2B_brlSXPV2pu7W90Xc","blah":123,"selfHash":"Eapp9Rz4xD0CT7VnplnK4nAb--YlkfAaq0PYPRV43XZY"}"#
    );
}
