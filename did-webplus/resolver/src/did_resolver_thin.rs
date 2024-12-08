use crate::{DIDResolver, Error, HTTPError, Result, REQWEST_CLIENT};

/// Use a trusted VDG to resolve a DID.  This amounts to completely outsourcing fetching and verification
/// of DID documents to the VDG.  This is useful for many reasons, and in particular for clients that can't
/// or do not want to implement the full DID resolution logic themselves.
pub struct DIDResolverThin {
    /// Specifies the URL of the "resolve" endpoint of the VDG to use for DID resolution.  The URL can
    /// omit the scheme (i.e. the "https://" portion), in which case, "https://" will be used.  The URL
    /// must not contain a query string or fragment.
    pub vdg_resolve_endpoint: url::Url,
}

#[async_trait::async_trait]
impl DIDResolver for DIDResolverThin {
    // TODO: Maybe specify HTTP client via trait here?
    async fn resolve_did_document_string(
        &self,
        did_query: &str,
        requested_did_document_metadata: did_webplus_core::RequestedDIDDocumentMetadata,
    ) -> Result<(String, did_webplus_core::DIDDocumentMetadata)> {
        if requested_did_document_metadata.constant
            || requested_did_document_metadata.idempotent
            || requested_did_document_metadata.currency
        {
            panic!("Temporary limitation: RequestedDIDDocumentMetadata must be empty for DIDResolverThin");
        }

        // Set the HTTP scheme is not specified.
        let vdg_resolve_endpoint = if self.vdg_resolve_endpoint.scheme().is_empty() {
            let mut vdg_resolve_endpoint = self.vdg_resolve_endpoint.clone();
            vdg_resolve_endpoint.set_scheme("https").unwrap();
            vdg_resolve_endpoint
        } else {
            self.vdg_resolve_endpoint.clone()
        };

        if !vdg_resolve_endpoint.path().ends_with('/') {
            panic!("VDG resolve endpoint must end with a slash");
        }
        if vdg_resolve_endpoint.query().is_some() {
            panic!("VDG resolve endpoint must not contain a query string");
        }
        if vdg_resolve_endpoint.fragment().is_some() {
            panic!("VDG resolve endpoint must not contain a fragment");
        }
        tracing::debug!("VDG resolve endpoint: {}", vdg_resolve_endpoint);
        let resolution_url = {
            let did_query_url_encoded = temp_hack_incomplete_url_encoded(did_query);
            let mut path = vdg_resolve_endpoint.path().to_string();
            assert!(path.ends_with('/'));
            path.push_str(did_query_url_encoded.as_str());
            let mut resolution_url = vdg_resolve_endpoint.clone();
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

        Ok((
            did_document_string,
            did_webplus_core::DIDDocumentMetadata {
                constant_o: None,
                idempotent_o: None,
                currency_o: None,
            },
        ))
    }
}

/// INCOMPLETE, TEMP HACK
fn temp_hack_incomplete_url_encoded(s: &str) -> String {
    s.replace('?', "%3F")
        .replace('=', "%3D")
        .replace('&', "%26")
}
