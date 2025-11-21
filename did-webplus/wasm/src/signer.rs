use crate::{into_js_value, KeyType, Result};
use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;

/// A Signer that has a specified key ID (kid field).
#[wasm_bindgen]
#[derive(Clone)]
pub struct Signer {
    /// This is the value to use for the "kid" field in the JWS header in JWS signatures. For example,
    /// "did:key:<base58enc-key>#<base58enc-key>" (see did_key::DIDResource) and
    /// "did:webplus:<hostname>:<path>:<root-self-hash>?selfHash=<query-self-hash>&versionId=<version-id>#<key-id>"
    /// (see did_webplus_core::DIDKeyResourceFullyQualified).
    key_id: String,
    /// The signer itself.
    signer_a: Arc<dyn signature_dyn::SignerDynT>,
}

impl Signer {
    pub fn key_id_as_str(&self) -> &str {
        self.key_id.as_str()
    }
}

#[wasm_bindgen]
impl Signer {
    pub fn did_key_generate_temp() -> Result<Self> {
        let key_type = signature_dyn::KeyType::Ed25519;
        let signer_b = did_webplus_cli_lib::private_key_generate(key_type);
        let signer_a = Arc::<dyn signature_dyn::SignerDynT>::from(signer_b);
        let did_resource =
            did_key::DIDResource::try_from(&signer_a.verifier_bytes().map_err(into_js_value)?)
                .map_err(into_js_value)?;
        let key_id = did_resource.to_string();
        Ok(Self { key_id, signer_a })
    }
    pub fn did_key_generate(key_type: KeyType) -> Result<Self> {
        let key_type = signature_dyn::KeyType::from(key_type);
        let signer_b = did_webplus_cli_lib::private_key_generate(key_type);
        let signer_a = Arc::<dyn signature_dyn::SignerDynT>::from(signer_b);
        let did_resource =
            did_key::DIDResource::try_from(&signer_a.verifier_bytes().map_err(into_js_value)?)
                .map_err(into_js_value)?;
        let key_id = did_resource.to_string();
        Ok(Self { key_id, signer_a })
    }
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }
}

impl std::ops::Deref for Signer {
    type Target = dyn signature_dyn::SignerDynT;
    fn deref(&self) -> &Self::Target {
        self.signer_a.as_ref()
    }
}
