use crate::{verifier_resolver_impl, DIDResolver, Result};
use std::sync::Arc;

/// Performs "raw" DID resolution, which only does a limited subset of verification, so should not
/// be used for any production purposes.  THIS IS INTENDED ONLY FOR DEVELOPMENT AND TESTING PURPOSES.
#[derive(Clone)]
pub struct DIDResolverRaw {
    pub http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DIDResolver for DIDResolverRaw {
    async fn resolve_did_document_string(
        &self,
        _did_query: &str,
        _requested_did_document_metadata: did_webplus_core::RequestedDIDDocumentMetadata,
    ) -> Result<(String, did_webplus_core::DIDDocumentMetadata)> {
        todo!("re-implement this");
    }
    fn as_verifier_resolver(&self) -> &dyn verifier_resolver::VerifierResolver {
        self
    }
    fn as_verifier_resolver_a(self: Arc<Self>) -> Arc<dyn verifier_resolver::VerifierResolver> {
        self
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl verifier_resolver::VerifierResolver for DIDResolverRaw {
    async fn resolve(
        &self,
        verifier_str: &str,
    ) -> verifier_resolver::Result<Box<dyn signature_dyn::VerifierDynT>> {
        verifier_resolver_impl(verifier_str, self).await
    }
}
