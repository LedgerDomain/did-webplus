use std::{
    ops::Deref,
    sync::{Arc, RwLock},
};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

pub type Error = JsValue;
pub type Result<T> = std::result::Result<T, JsValue>;

pub fn into_js_value<T: std::fmt::Display>(t: T) -> JsValue {
    JsValue::from(t.to_string())
}

#[wasm_bindgen(start)]
pub fn main() -> Result<()> {
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

/// A Signer that has a specified key ID (kid field).
#[wasm_bindgen]
pub struct Signer {
    /// This is the value to use for the "kid" field in the JWS header in JWS signatures. For example,
    /// "did:key:<base58enc-key>#<base58enc-key>" (see did_key::DIDResource) and
    /// "did:webplus:<host>:<path>:<root-self-hash>?selfHash=<query-self-hash>&versionId=<version-id>#<key-id>"
    /// (see did_webplus_core::DIDKeyResourceFullyQualified).
    key_id: String,
    /// The signer itself.
    signer_b: Box<dyn selfsign::Signer>,
}

#[wasm_bindgen]
impl Signer {
    pub fn did_key_generate_temp() -> Result<Self> {
        let key_type = selfsign::KeyType::Ed25519;
        let signer_b = did_webplus_cli_lib::priv_key_generate(key_type);
        let did_resource = did_key::DIDResource::try_from(&signer_b.verifier().to_verifier_bytes())
            .map_err(into_js_value)?;
        let key_id = did_resource.to_string();
        Ok(Self { key_id, signer_b })
    }
    pub fn did_key_generate(key_type: selfsign::KeyType) -> Result<Self> {
        let signer_b = did_webplus_cli_lib::priv_key_generate(key_type);
        let did_resource = did_key::DIDResource::try_from(&signer_b.verifier().to_verifier_bytes())
            .map_err(into_js_value)?;
        let key_id = did_resource.to_string();
        Ok(Self { key_id, signer_b })
    }
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }
}

impl Signer {
    pub fn signer(&self) -> &dyn selfsign::Signer {
        self.signer_b.as_ref()
    }
}

/// NOTE: The payload should be bytes (Vec<u8>), but for now just use a String.
#[wasm_bindgen]
pub fn jws_sign(
    // payload_bytes: Vec<u8>,
    payload_string: String,
    payload_presence: did_webplus_jws::JWSPayloadPresence,
    payload_encoding: did_webplus_jws::JWSPayloadEncoding,
    signer: &Signer,
) -> Result<String> {
    let jws = did_webplus_jws::JWS::signed(
        signer.key_id(),
        &mut payload_string.as_bytes(),
        payload_presence,
        payload_encoding,
        signer.signer(),
    )
    .map_err(into_js_value)?;
    Ok(jws.into_string())
}

/// A VerifierResolver that can resolve did:key values.  TODO: did:webplus values.
// TODO: Because this only contains an Arc, this should implement Clone.
#[wasm_bindgen]
pub struct VerifierResolver {
    verifier_resolver_l: Arc<RwLock<dyn verifier_resolver::VerifierResolver>>,
}

#[wasm_bindgen]
impl VerifierResolver {
    pub fn for_did_key() -> Self {
        Self {
            verifier_resolver_l: Arc::new(RwLock::new(did_key::DIDKeyVerifierResolver)),
        }
    }
}

impl VerifierResolver {
    pub fn verifier_resolver_l(&self) -> &Arc<RwLock<dyn verifier_resolver::VerifierResolver>> {
        &self.verifier_resolver_l
    }
}

/// Note that the return value will be null, but will throw an error if the verification fails.
// TODO: Support detached payload later.
// TODO: Figure out if #[wasm_bindgen] works directly on an async fn without the need for js_sys::Promise
#[wasm_bindgen]
pub fn jws_verify(jws: String, verifier_resolver: &VerifierResolver) -> js_sys::Promise {
    let verifier_resolver_l = verifier_resolver.verifier_resolver_l().clone();
    wasm_bindgen_futures::future_to_promise(async move {
        let jws = did_webplus_jws::JWS::try_from(jws).map_err(into_js_value)?;
        let verifier_resolver_g = verifier_resolver_l.read().unwrap();
        did_webplus_cli_lib::jws_verify(&jws, None, verifier_resolver_g.deref())
            .await
            .map_err(into_js_value)?;
        Ok(JsValue::null())
    })
}

/// Note that the return value will be null, but will throw an error if the verification fails.
// TODO: Support detached payload later.
// TEMP HACK: Just hardcode the did:key VerifierResolver for now.
#[wasm_bindgen]
pub fn jws_verify_temphack(jws: String) -> js_sys::Promise {
    wasm_bindgen_futures::future_to_promise(async move {
        let jws = did_webplus_jws::JWS::try_from(jws).map_err(into_js_value)?;
        did_webplus_cli_lib::jws_verify(&jws, None, &did_key::DIDKeyVerifierResolver)
            .await
            .map_err(into_js_value)?;
        Ok(JsValue::from("VALID"))
    })
}

#[wasm_bindgen]
pub fn vjson_default_schema() -> String {
    vjson_core::DEFAULT_SCHEMA.jcs.clone()
}

// TODO: Should this accept and return JsValue?  Or &str?
#[wasm_bindgen]
pub fn vjson_self_hash_temphack(json_string: String) -> js_sys::Promise {
    tracing::debug!("hippo 1; json_string: {}", json_string);
    wasm_bindgen_futures::future_to_promise(async move {
        let json_value: serde_json::Value =
            serde_json::from_str(&json_string).map_err(into_js_value)?;
        tracing::debug!("hippo 2");
        let vjson_store = VJSONStore::new_mock().await?;
        tracing::debug!("hippo 3");
        let vjson_resolver = vjson_store.as_resolver();
        tracing::debug!("hippo 4");
        let vjson_value = did_webplus_cli_lib::vjson_self_hash(
            json_value,
            vjson_resolver.vjson_resolver_l.read().unwrap().deref(),
        )
        .await
        .map_err(into_js_value)?;
        tracing::debug!("hippo 5");
        // TODO: Probably use JCS here
        Ok(JsValue::from(vjson_value.to_string()))
    })
}

// TODO: Should this accept and return JsValue?  Or &str?
#[wasm_bindgen]
pub async fn vjson_self_hash(json_string: String, vjson_store: &VJSONStore) -> Result<String> {
    let json_value: serde_json::Value =
        serde_json::from_str(&json_string).map_err(into_js_value)?;
    let vjson_resolver = vjson_store.as_resolver();
    let vjson_value = did_webplus_cli_lib::vjson_self_hash(
        json_value,
        vjson_resolver.vjson_resolver_l.read().unwrap().deref(),
    )
    .await
    .map_err(into_js_value)?;
    // TODO: Probably use JCS here
    Ok(vjson_value.to_string())
}

// TODO: Should this accept and return JsValue?  Or &str?
#[wasm_bindgen]
pub async fn vjson_verify(
    json_string: String,
    vjson_resolver: &VJSONResolver,
    verifier_resolver: &VerifierResolver,
) -> Result<JsValue> {
    // TODO: Using JsValue will presumably be more efficient.
    let json_value: serde_json::Value =
        serde_json::from_str(&json_string).map_err(into_js_value)?;
    let self_hash = did_webplus_cli_lib::vjson_verify(
        &json_value,
        vjson_resolver.vjson_resolver_l.read().unwrap().deref(),
        verifier_resolver
            .verifier_resolver_l
            .read()
            .unwrap()
            .deref(),
    )
    .await
    .map_err(into_js_value)?;
    Ok(JsValue::from(self_hash.into_string()))
}

// TODO: Because this only contains an Arc, this should implement Clone.
// TODO: Maybe this type is unnecessary, and the VJSONStore should just be used directly.
#[wasm_bindgen]
pub struct VJSONStore {
    vjson_store: vjson_store::VJSONStore,
    // vjson_resolver: vjson_store::VJSONStoreAsResolver,
}

#[wasm_bindgen]
impl VJSONStore {
    pub async fn new_mock() -> Result<Self> {
        let vjson_storage_mock = vjson_storage_mock::VJSONStorageMock::new();
        let vjson_store = vjson_store::VJSONStore::new(Arc::new(vjson_storage_mock))
            .await
            .map_err(into_js_value)?;
        // let vjson_store_l = Arc::new(RwLock::new(vjson_store));
        // let vjson_resolver = vjson_store::VJSONStoreAsResolver {
        //     vjson_store_l: vjson_store_l.clone(),
        // };
        Ok(Self {
            vjson_store,
            // vjson_resolver,
        })
    }
}

impl VJSONStore {
    //     pub fn vjson_resolver(&self) -> &dyn vjson_core::VJSONResolver {
    //         &self.vjson_store_l
    //     }
    pub fn as_resolver(&self) -> VJSONResolver {
        let vjson_store_as_resolver = vjson_store::VJSONStoreAsResolver {
            vjson_store: self.vjson_store.clone(),
        };
        VJSONResolver {
            vjson_resolver_l: Arc::new(RwLock::new(vjson_store_as_resolver)),
        }
    }
}

#[wasm_bindgen]
pub struct VJSONResolver {
    vjson_resolver_l: Arc<RwLock<dyn vjson_core::VJSONResolver>>,
}
