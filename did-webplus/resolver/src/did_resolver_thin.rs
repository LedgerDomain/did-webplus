use did_webplus_core::{
    DIDDocumentMetadata, DIDResolutionMetadata, DIDResolutionOptions, HTTPHeadersFor, HTTPOptions,
    HTTPSchemeOverride,
};

use crate::{DIDResolver, Error, HTTPError, REQWEST_CLIENT, Result, verifier_resolver_impl};
use std::sync::Arc;

/// Use a trusted VDG to resolve a DID.  This amounts to completely outsourcing fetching and verification
/// of DID documents to the VDG.  This is useful for many reasons, and in particular for clients that can't
/// or do not want to implement the full DID resolution logic themselves.
#[derive(Clone)]
pub struct DIDResolverThin {
    /// Specifies the "base" URL of the VDG to use.  URLs for various operations of the VDG will be constructed from this.
    vdg_base_url: url::Url,
    http_headers_for_o: Option<HTTPHeadersFor>,
}

impl DIDResolverThin {
    pub fn new(vdg_host: &str, http_options_o: Option<HTTPOptions>) -> Result<Self> {
        // Set the HTTP scheme appropriately.
        let http_scheme = HTTPSchemeOverride::determine_http_scheme_for_host_from(
            http_options_o.as_ref().map(|o| &o.http_scheme_override),
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
        Ok(Self {
            vdg_base_url,
            http_headers_for_o: http_options_o.map(|o| o.http_headers_for),
        })
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
        did_resolution_options: DIDResolutionOptions,
    ) -> Result<(String, DIDDocumentMetadata, DIDResolutionMetadata)> {
        tracing::debug!(
            "DIDResolverThin::resolve_did_document_string; did_query: {}; did_resolution_options: {:?}",
            did_query,
            did_resolution_options,
        );

        let vdg_resolution_url = {
            let mut vdg_resolution_url = self.vdg_base_url.clone();
            vdg_resolution_url
                .path_segments_mut()
                .unwrap()
                .push("webplus");
            vdg_resolution_url.path_segments_mut().unwrap().push("v1");
            vdg_resolution_url
                .path_segments_mut()
                .unwrap()
                .push("resolve");
            // Note that `push` will percent-encode did_query!
            vdg_resolution_url
                .path_segments_mut()
                .unwrap()
                .push(did_query);
            tracing::debug!("DID resolution URL: {}", vdg_resolution_url);
            vdg_resolution_url
        };
        let header_map = {
            let mut header_map = reqwest::header::HeaderMap::new();
            if did_resolution_options.request_creation {
                header_map.insert(
                    "X-DID-Request-Creation-Metadata",
                    reqwest::header::HeaderValue::from_static("true"),
                );
            }
            if did_resolution_options.request_next {
                header_map.insert(
                    "X-DID-Request-Next-Metadata",
                    reqwest::header::HeaderValue::from_static("true"),
                );
            }
            if did_resolution_options.request_latest {
                header_map.insert(
                    "X-DID-Request-Latest-Metadata",
                    reqwest::header::HeaderValue::from_static("true"),
                );
            }
            if did_resolution_options.request_deactivated {
                header_map.insert(
                    "X-DID-Request-Deactivated-Metadata",
                    reqwest::header::HeaderValue::from_static("true"),
                );
            }
            if did_resolution_options.local_resolution_only {
                header_map.insert(
                    "X-DID-Local-Resolution-Only",
                    reqwest::header::HeaderValue::from_static("true"),
                );
            }
            if let Some(http_headers_for) = self.http_headers_for_o.as_ref() {
                let http_header_v = http_headers_for
                    .http_headers_for_hostname(vdg_resolution_url.host_str().unwrap())
                    .unwrap_or_default();
                for http_header in http_header_v {
                    header_map.insert(
                        reqwest::header::HeaderName::from_bytes(http_header.name.as_bytes()).map_err(|e| Error::GenericError(format!("Failed to parse HTTP header name from {:?}; error was: {}", http_header.name, e).into()))?,
                        reqwest::header::HeaderValue::from_str(&http_header.value).map_err(|e| Error::GenericError(format!("Failed to parse HTTP header {:?} value to HeaderValue; error was: {}", http_header, e).into()))?,
                    );
                }
            }
            header_map
        };
        // TODO: Consolidate all the REQWEST_CLIENT-s
        let response = REQWEST_CLIENT
            .get(vdg_resolution_url)
            .headers(header_map)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Error sending request to VDG: {}", e);
                // TODO: Produce Error::DIDResolutionFailure2
                Error::DIDResolutionFailure(HTTPError {
                    status_code: e.status().unwrap(),
                    description: e.to_string().into(),
                })
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Error getting response from VDG: {}", e);
                // TODO: Produce Error::DIDResolutionFailure2
                Error::DIDResolutionFailure(HTTPError {
                    status_code: e.status().unwrap(),
                    description: e.to_string().into(),
                })
            })?;
        // Read DIDDocumentMetadata out of response headers
        let did_document_metadata = {
            let did_document_metadata_str = response
                .headers()
                .get("X-DID-Document-Metadata")
                .ok_or_else(|| {
                    Error::DIDResolutionFailure(HTTPError {
                        status_code: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        description: "X-DID-Document-Metadata header not found in VDG's response"
                            .into(),
                    })
                })?
                .to_str()
                .map_err(|e| {
                    // TODO: Produce Error::DIDResolutionFailure2
                    Error::DIDResolutionFailure(HTTPError {
                        status_code: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        description: format!(
                            "Failed to convert X-DID-Document-Metadata header to string in VDG's response; error was: {}",
                            e
                        ).into(),
                    })
                })?;
            tracing::debug!(
                "X-DID-Document-Metadata header: {}",
                did_document_metadata_str
            );
            let did_document_metadata =
                serde_json::from_str(&did_document_metadata_str).map_err(|_| {
                    Error::DIDResolutionFailure(HTTPError {
                    status_code: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    description:
                        "Failed to deserialize X-DID-Document-Metadata header from VDG's response"
                            .into(),
                })
                })?;
            tracing::debug!(
                "Deserialized DIDDocumentMetadata: {:?}",
                did_document_metadata
            );
            did_document_metadata
        };
        // Read DIDResolutionMetadata out of response headers
        let did_resolution_metadata = {
            let did_resolution_metadata_str = response
                .headers()
                .get("X-DID-Resolution-Metadata")
                .ok_or_else(|| {
                    // TODO: Produce Error::DIDResolutionFailure2
                    Error::DIDResolutionFailure(HTTPError {
                        status_code: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        description: "X-DID-Resolution-Metadata header not found in VDG's response"
                            .into(),
                    })
                })?
                .to_str()
                .map_err(|e| {
                    // TODO: Produce Error::DIDResolutionFailure2
                    Error::DIDResolutionFailure(HTTPError {
                        status_code: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        description: format!(
                            "Failed to convert X-DID-Resolution-Metadata header to string in VDG's response; error was: {}",
                            e
                        ).into(),
                    })
                })?;
            tracing::debug!(
                "X-DID-Resolution-Metadata header: {}",
                did_resolution_metadata_str
            );
            let did_resolution_metadata = serde_json::from_str(&did_resolution_metadata_str)
                .map_err(|_| {
                    // TODO: Produce Error::DIDResolutionFailure2
                    Error::DIDResolutionFailure(HTTPError {
                    status_code: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    description:
                        "Failed to deserialize X-DID-Resolution-Metadata header from VDG's response"
                            .into(),
                })
                })?;
            tracing::debug!(
                "Deserialized DIDResolutionMetadata: {:?}",
                did_resolution_metadata
            );
            did_resolution_metadata
        };
        // Read DIDDocument string out of response body
        let did_document_string = response.text().await.map_err(|e| {
            // TODO: Produce Error::DIDResolutionFailure2
            Error::DIDResolutionFailure(HTTPError {
                status_code: e.status().unwrap(),
                description: e.to_string().into(),
            })
        })?;

        tracing::trace!(
            "DIDResolverThin::resolve_did_document_string; successfully resolved DID document: {}",
            did_document_string
        );
        Ok((
            did_document_string,
            did_document_metadata,
            did_resolution_metadata,
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
    ) -> verifier_resolver::Result<Box<dyn signature_dyn::VerifierDynT>> {
        verifier_resolver_impl(verifier_str, self).await
    }
}
