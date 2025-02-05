use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;

/// A VerifierResolver that can resolve did:key values.  TODO: did:webplus values.
#[wasm_bindgen]
#[derive(Clone)]
pub struct VerifierResolver(Arc<dyn verifier_resolver::VerifierResolver>);

#[wasm_bindgen]
impl VerifierResolver {
    pub fn for_did_key() -> Self {
        Self(Arc::new(did_key::DIDKeyVerifierResolver))
    }
}

impl std::ops::Deref for VerifierResolver {
    type Target = dyn verifier_resolver::VerifierResolver;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
