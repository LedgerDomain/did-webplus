mod did;
mod did_doc_store;
mod did_resolver;
mod jws;
mod signer;
mod verifier_resolver;
mod vjson;
mod vjson_resolver;
mod vjson_store;

pub use crate::{
    did::did_resolve,
    did_doc_store::DIDDocStore,
    did_resolver::DIDResolver,
    signer::Signer,
    verifier_resolver::VerifierResolver,
    vjson::{vjson_default_schema, vjson_self_hash, vjson_verify},
    vjson_resolver::VJSONResolver,
    vjson_store::VJSONStore,
};
pub type Error = JsValue;
pub type Result<T> = std::result::Result<T, JsValue>;

use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

pub fn into_js_value<T: std::fmt::Display>(t: T) -> JsValue {
    JsValue::from(t.to_string())
}

#[wasm_bindgen(start)]
pub fn start() -> Result<()> {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Debug));
    Ok(())
}

/*
TODO
-   Wallet
-   WalletStorage
-   VJSONStorage
-   DIDKeySigner
-   DIDWebplusWalletSigner kind of a signer (probably has a wallet, DID, and key id)


 */
