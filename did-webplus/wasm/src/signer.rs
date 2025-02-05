use crate::{into_js_value, Result};
use wasm_bindgen::prelude::wasm_bindgen;

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

impl std::ops::Deref for Signer {
    type Target = dyn selfsign::Signer;
    fn deref(&self) -> &Self::Target {
        self.signer_b.as_ref()
    }
}
