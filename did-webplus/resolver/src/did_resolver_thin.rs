use crate::{verifier_resolver_impl, DIDResolver, Error, HTTPError, Result, REQWEST_CLIENT};
use std::sync::Arc;

/// Use a trusted VDG to resolve a DID.  This amounts to completely outsourcing fetching and verification
/// of DID documents to the VDG.  This is useful for many reasons, and in particular for clients that can't
/// or do not want to implement the full DID resolution logic themselves.
#[derive(Clone)]
pub struct DIDResolverThin {
    /// Specifies the "base" URL of the VDG to use.  URLs for various operations of the VDG will be constructed from this.
    vdg_base_url: url::Url,
}

impl DIDResolverThin {
    pub fn new(
        vdg_host: &str,
        http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<Self> {
        // Set the HTTP scheme appropriately.
        let http_scheme =
            did_webplus_core::HTTPSchemeOverride::determine_http_scheme_for_host_from(
                http_scheme_override_o,
                vdg_host,
            )
            .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
        let vdg_base_url =
            url::Url::parse(&format!("{}://{}/", http_scheme, vdg_host)).map_err(|e| {
                Error::MalformedVDGHost(
                    format!(
                        "Failed to construct VDG base URL from VDG host {:?}: {}",
                        vdg_host, e
                    )
                    .into(),
                )
            })?;

        if vdg_base_url.query().is_some() {
            return Err(Error::MalformedVDGHost(
                "VDG resolve endpoint must not contain a query string".into(),
            ));
        }
        if vdg_base_url.fragment().is_some() {
            return Err(Error::MalformedVDGHost(
                "VDG resolve endpoint must not contain a fragment".into(),
            ));
        }
        tracing::debug!("VDG base URL: {}", vdg_base_url);
        Ok(Self { vdg_base_url })
    }
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

        let resolution_url = {
            let mut resolution_url = self.vdg_base_url.clone();
            resolution_url.path_segments_mut().unwrap().push("webplus");
            resolution_url.path_segments_mut().unwrap().push("v1");
            resolution_url.path_segments_mut().unwrap().push("resolve");
            // Note that `push` will percent-encode did_query!
            resolution_url.path_segments_mut().unwrap().push(did_query);
            tracing::debug!("DID resolution URL: {}", resolution_url);
            resolution_url
        };
        // TODO: Consolidate all the REQWEST_CLIENT-s
        let response = REQWEST_CLIENT
            .get(resolution_url)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Error sending request to VDG: {}", e);
                Error::DIDResolutionFailure(HTTPError {
                    status_code: e.status().unwrap(),
                    description: e.to_string().into(),
                })
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Error getting response from VDG: {}", e);
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
