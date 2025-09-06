use crate::{verifier_resolver_impl, DIDResolver, Error, HTTPError, Result, REQWEST_CLIENT};
use std::sync::Arc;

/// Use a trusted VDG to resolve a DID.  This amounts to completely outsourcing fetching and verification
/// of DID documents to the VDG.  This is useful for many reasons, and in particular for clients that can't
/// or do not want to implement the full DID resolution logic themselves.
#[derive(Clone)]
pub struct DIDResolverThin {
    /// Specifies the URL of the "resolve" endpoint of the VDG to use for DID resolution.  The URL can
    /// omit the scheme (i.e. the "https://" portion), in which case, "https://" will be used.  The URL
    /// must not contain a query string or fragment.
    pub vdg_resolve_endpoint_url: url::Url,
    /// Specifies optional HTTP scheme overrides for the DID Resolver.  See `HTTPSchemeOverride` for
    /// more details.
    pub http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DIDResolver for DIDResolverThin {
    // TODO: Maybe specify HTTP client via trait here?  I.e. for wasm vs native.  Unless reqwest already
    // handles wasm correctly.
    async fn resolve_did_document_string(
        &self,
        did_query: &str,
        requested_did_document_metadata: did_webplus_core::RequestedDIDDocumentMetadata,
    ) -> Result<(String, did_webplus_core::DIDDocumentMetadata)> {
        tracing::debug!(
            "DIDResolverThin::resolve_did_document_string; did_query: {}; requested_did_document_metadata: {:?}",
            did_query,
            requested_did_document_metadata
        );

        if requested_did_document_metadata.constant
            || requested_did_document_metadata.idempotent
            || requested_did_document_metadata.currency
        {
            panic!("Temporary limitation: RequestedDIDDocumentMetadata must be empty for DIDResolverThin");
        }

        // Set the HTTP scheme is not specified.
        let mut vdg_resolve_endpoint_url = if self.vdg_resolve_endpoint_url.scheme().is_empty() {
            let mut vdg_resolve_endpoint_url = self.vdg_resolve_endpoint_url.clone();
            vdg_resolve_endpoint_url.set_scheme("https").unwrap();
            vdg_resolve_endpoint_url
        } else {
            self.vdg_resolve_endpoint_url.clone()
        };

        if let Some(http_scheme_override) = &self.http_scheme_override_o {
            let http_scheme = http_scheme_override
                .determine_http_scheme_for_hostname(vdg_resolve_endpoint_url.host_str().unwrap());
            vdg_resolve_endpoint_url.set_scheme(http_scheme).unwrap();
        }

        if !vdg_resolve_endpoint_url.path().ends_with('/') {
            panic!("VDG resolve endpoint must end with a slash");
        }
        if vdg_resolve_endpoint_url.query().is_some() {
            panic!("VDG resolve endpoint must not contain a query string");
        }
        if vdg_resolve_endpoint_url.fragment().is_some() {
            panic!("VDG resolve endpoint must not contain a fragment");
        }
        tracing::debug!("VDG resolve endpoint: {}", vdg_resolve_endpoint_url);
        let resolution_url = {
            let did_query_url_encoded = temp_hack_incomplete_percent_encoded(did_query);
            let mut path = vdg_resolve_endpoint_url.path().to_string();
            assert!(path.ends_with('/'));
            path.push_str(did_query_url_encoded.as_str());
            let mut resolution_url = vdg_resolve_endpoint_url.clone();
            resolution_url.set_path(path.as_str());
            tracing::debug!("DID resolution URL: {}", resolution_url);
            resolution_url
        };
        // TODO: Consolidate all the REQWEST_CLIENT-s
        let response = REQWEST_CLIENT
            .get(resolution_url)
            .send()
            .await
            .map_err(|e| {
                Error::DIDResolutionFailure(HTTPError {
                    status_code: e.status().unwrap(),
                    description: e.to_string().into(),
                })
            })?
            .error_for_status()
            .map_err(|e| {
                Error::DIDResolutionFailure(HTTPError {
                    status_code: e.status().unwrap(),
                    description: e.to_string().into(),
                })
            })?;
        let did_document_string = response.text().await.map_err(|e| {
            Error::DIDResolutionFailure(HTTPError {
                status_code: e.status().unwrap(),
                description: e.to_string().into(),
            })
        })?;

        // TODO: Implement metadata (requires VDG support)

        tracing::trace!(
            "DIDResolverThin::resolve_did_document_string; successfully resolved DID document: {}",
            did_document_string
        );
        Ok((
            did_document_string,
            did_webplus_core::DIDDocumentMetadata {
                constant_o: None,
                idempotent_o: None,
                currency_o: None,
            },
        ))
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
impl verifier_resolver::VerifierResolver for DIDResolverThin {
    async fn resolve(
        &self,
        verifier_str: &str,
    ) -> verifier_resolver::Result<Box<dyn selfsign::Verifier>> {
        verifier_resolver_impl(verifier_str, self).await
    }
}

/// INCOMPLETE, TEMP HACK -- TODO: use percent-encoding crate
fn temp_hack_incomplete_percent_encoded(s: &str) -> String {
    // Note that the '%' -> "%25" replacement must happen first.
    s.replace('%', "%25")
        .replace('?', "%3F")
        .replace('=', "%3D")
        .replace('&', "%26")
}
