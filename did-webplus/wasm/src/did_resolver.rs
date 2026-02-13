use crate::{DIDDocStore, HTTPOptions, Result, into_js_value};
use std::{ops::Deref, sync::Arc};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

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
        vdg_host_o: Option<String>,
        http_options_o: Option<HTTPOptions>,
    ) -> Result<Self> {
        let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
            did_doc_store.into_inner(),
            vdg_host_o.as_deref(),
            http_options_o.map(|o| o.into()),
        )
        .map_err(into_js_value)?;
        Ok(Self(Arc::new(did_resolver_full)))
    }
    /// Create a "thin" DIDResolver that operates against the given trusted VDG.
    pub fn new_thin(vdg_host: &str, http_options_o: Option<HTTPOptions>) -> Result<Self> {
        let did_resolver_thin =
            did_webplus_resolver::DIDResolverThin::new(vdg_host, http_options_o.map(|o| o.into()))
                .map_err(into_js_value)?;
        Ok(Self(Arc::new(did_resolver_thin)))
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
    ) -> verifier_resolver::Result<Box<dyn signature_dyn::VerifierDynT>> {
        self.as_verifier_resolver().resolve(verifier_str).await
    }
}

/// Resolve the given DID query using the given DIDResolver.  Returns the JCS-serialized DID document as a String.
#[wasm_bindgen]
pub fn did_resolve(did_query: String, did_resolver: &DIDResolver) -> js_sys::Promise {
    let did_resolver = did_resolver.clone();
    // TEMP HACK
    let did_resolution_options = did_webplus_core::DIDResolutionOptions::no_metadata(false);
    wasm_bindgen_futures::future_to_promise(async move {
        let (did_document_jcs, _did_document_metadata, _did_resolution_metadata) =
            did_webplus_cli_lib::did_resolve_string(
                did_query.as_str(),
                did_resolver.deref(),
                did_resolution_options,
            )
            .await
            .map_err(into_js_value)?;
        Ok(JsValue::from(did_document_jcs))
    })
}
