use crate::DIDResolver;
use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;

/// A VerifierResolver is what turns a key ID (e.g. the "kid" field of a JWS) into a verifier
/// (i.e. public key) for use in verifying signatures.
#[wasm_bindgen]
#[derive(Clone)]
pub struct VerifierResolver(Arc<verifier_resolver::VerifierResolverMap>);

#[wasm_bindgen]
impl VerifierResolver {
    /// Creates a VerifierResolver that handles no verifiers (this is used when you know for a fact
    /// there will be no signatures to verify).
    pub fn new_empty() -> Self {
        let verifier_resolver_map = verifier_resolver::VerifierResolverMap::new();
        Self(Arc::new(verifier_resolver_map))
    }
    /// Creates a VerifierResolver capable of resolving did:key-based verifiers.
    pub fn new_with_did_key() -> Self {
        let verifier_resolver_map = verifier_resolver::VerifierResolverMap::new()
            .with("did:key:", Box::new(did_key::DIDKeyVerifierResolver));
        Self(Arc::new(verifier_resolver_map))
    }
    /// Creates a VerifierResolver capable of resolving did:webplus-based verifiers.
    pub fn new_with_did_webplus(did_resolver: DIDResolver) -> Self {
        let verifier_resolver_map = verifier_resolver::VerifierResolverMap::new()
            .with("did:webplus:", Box::new(did_resolver));
        Self(Arc::new(verifier_resolver_map))
    }
    /// Creates a VerifierResolver capable of resolving did:key-based and did:webplus-based verifiers.
    pub fn new_with_did_key_and_did_webplus(did_resolver: DIDResolver) -> Self {
        let verifier_resolver_map = verifier_resolver::VerifierResolverMap::new()
            .with("did:key:", Box::new(did_key::DIDKeyVerifierResolver))
            .with("did:webplus:", Box::new(did_resolver));
        Self(Arc::new(verifier_resolver_map))
    }
}

impl std::ops::Deref for VerifierResolver {
    type Target = dyn verifier_resolver::VerifierResolver;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
