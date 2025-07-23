use crate::{into_js_value, DIDDocStore, HTTPSchemeOverride, Result};
use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct DIDResolver(Arc<dyn did_webplus_resolver::DIDResolver>);

impl DIDResolver {
    pub fn new(did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>) -> Self {
        Self(did_resolver_a)
    }
}

#[wasm_bindgen]
impl DIDResolver {
    /// Create a "full" DIDResolver using the given DIDDocStore, and with given http_scheme override.
    /// Note that http_scheme is a temporary parameter that is mostly for testing/development and
    /// will change in the future.
    pub fn new_full(
        did_doc_store: DIDDocStore,
        http_scheme_override_o: Option<HTTPSchemeOverride>,
    ) -> Result<Self> {
        let did_resolver = did_webplus_resolver::DIDResolverFull {
            did_doc_store: did_doc_store.into_inner(),
            http_scheme_override_o: http_scheme_override_o.map(|o| o.into()),
            fetch_pattern: did_webplus_resolver::FetchPattern::Serial,
        };
        Ok(Self(Arc::new(did_resolver)))
    }
    /// Create a "thin" DIDResolver that operates against the given trusted VDG.
    pub fn new_thin(
        vdg_resolve_endpoint: &str,
        http_scheme_override_o: Option<HTTPSchemeOverride>,
    ) -> Result<Self> {
        let vdg_resolve_endpoint_url =
            url::Url::parse(vdg_resolve_endpoint).map_err(into_js_value)?;
        let did_resolver = did_webplus_resolver::DIDResolverThin {
            vdg_resolve_endpoint_url,
            http_scheme_override_o: http_scheme_override_o.map(|o| o.into()),
        };
        Ok(Self(Arc::new(did_resolver)))
    }
    /// Create a "raw" DIDResolver that bypasses all verification and only fetches DID documents.
    /// This is only meant for testing/development and should never be used in production.
    pub fn new_raw(http_scheme_override_o: Option<HTTPSchemeOverride>) -> Result<Self> {
        let did_resolver = did_webplus_resolver::DIDResolverRaw {
            http_scheme_override_o: http_scheme_override_o.map(|o| o.into()),
        };
        Ok(Self(Arc::new(did_resolver)))
    }
}

impl std::ops::Deref for DIDResolver {
    type Target = dyn did_webplus_resolver::DIDResolver;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl verifier_resolver::VerifierResolver for DIDResolver {
    async fn resolve(
        &self,
        verifier_str: &str,
    ) -> verifier_resolver::Result<Box<dyn selfsign::Verifier>> {
        self.as_verifier_resolver().resolve(verifier_str).await
    }
}
