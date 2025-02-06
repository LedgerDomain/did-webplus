use std::ops::Deref;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
#[allow(unused)]
async fn test_vjson() {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Debug));

    let vjson_store = did_webplus_wasm::VJSONStore::new_mock()
        .await
        .expect("pass");

    let json_string = r#"{"blah":123, "$id":"vjson:///"}"#.to_string();
    let vjson_value = did_webplus_cli_lib::vjson_self_hash(
        serde_json::from_str(&json_string).expect("pass"),
        vjson_store.as_resolver().deref(),
    )
    .await
    .expect("pass");
    let vjson_string = serde_json_canonicalizer::to_string(&vjson_value).expect("pass");

    assert_eq!(
        vjson_string.as_str(),
        r#"{"$id":"vjson:///Eapp9Rz4xD0CT7VnplnK4nAb--YlkfAaq0PYPRV43XZY","$schema":"vjson:///EnD4KcLMLmGSjEliVPgBdMsEC2B_brlSXPV2pu7W90Xc","blah":123,"selfHash":"Eapp9Rz4xD0CT7VnplnK4nAb--YlkfAaq0PYPRV43XZY"}"#
    );
}
