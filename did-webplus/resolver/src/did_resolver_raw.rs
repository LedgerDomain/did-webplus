use crate::{verifier_resolver_impl, DIDResolver, Error, HTTPError, Result, REQWEST_CLIENT};

/// Performs "raw" DID resolution, which only does a limited subset of verification, so should not
/// be used for any production purposes.  THIS IS INTENDED ONLY FOR DEVELOPMENT AND TESTING PURPOSES.
#[derive(Clone)]
pub struct DIDResolverRaw {
    /// TEMP HACK: Specify the scheme used for HTTP requests.  Must be either "https" or "http".  This is
    /// only useful for testing and potentially for VPC-like situations.
    pub http_scheme: &'static str,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DIDResolver for DIDResolverRaw {
    async fn resolve_did_document_string(
        &self,
        did_query: &str,
        requested_did_document_metadata: did_webplus_core::RequestedDIDDocumentMetadata,
    ) -> Result<(String, did_webplus_core::DIDDocumentMetadata)> {
        if requested_did_document_metadata.constant
            || requested_did_document_metadata.idempotent
            || requested_did_document_metadata.currency
        {
            panic!("Temporary limitation: RequestedDIDDocumentMetadata must be empty for DIDResolverRaw");
        }

        let did_resolution_url = if let Ok(did_fully_qualified) =
            did_webplus_core::DIDFullyQualifiedStr::new_ref(did_query)
        {
            did_fully_qualified.resolution_url(self.http_scheme)
        } else if let Ok(did) = did_webplus_core::DIDStr::new_ref(did_query) {
            did.resolution_url(self.http_scheme)
        } else {
            return Err(Error::MalformedDIDQuery(did_query.to_string().into()));
        };

        let response = REQWEST_CLIENT
            .get(did_resolution_url)
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

        // TODO: Implement metadata
        let did_document_metadata = did_webplus_core::DIDDocumentMetadata {
            constant_o: None,
            idempotent_o: None,
            currency_o: None,
        };

        Ok((did_document_string, did_document_metadata))
    }
}

#[async_trait::async_trait]
impl verifier_resolver::VerifierResolver for DIDResolverRaw {
    async fn resolve(
        &self,
        verifier_str: &str,
    ) -> verifier_resolver::Result<Box<dyn selfsign::Verifier>> {
        verifier_resolver_impl(verifier_str, self).await
    }
}
