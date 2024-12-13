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

// #[wasm_bindgen(start)]
// fn main() {
//     console_error_panic_hook::set_once();
// }

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
// TODO: Because this only contains an Arc, this should implement Clone, and even Copy.
#[wasm_bindgen]
pub struct VerifierResolver {
    verifier_resolver_l: Arc<RwLock<dyn verifier_resolver::VerifierResolver>>,
}

#[wasm_bindgen]
impl VerifierResolver {
    pub fn for_did_key() -> Self {
        Self {
            verifier_resolver_l: Arc::new(RwLock::new(verifier_resolver::VerifierResolverDIDKey)),
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
#[wasm_bindgen]
pub fn jws_verify_temphack(jws: String) -> js_sys::Promise {
    wasm_bindgen_futures::future_to_promise(async move {
        let jws = did_webplus_jws::JWS::try_from(jws).map_err(into_js_value)?;
        did_webplus_cli_lib::jws_verify(&jws, None, &verifier_resolver::VerifierResolverDIDKey)
            .await
            .map_err(into_js_value)?;
        Ok(JsValue::from("VALID"))
    })
}
