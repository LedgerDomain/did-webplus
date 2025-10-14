use did_webplus_core::{
    DIDDocument, DIDDocumentMetadata, DIDResolutionMetadata, DIDResolutionOptions,
};

use crate::{Error, Result};
use std::sync::Arc;

/// Note that a DIDResolver is a VerifierResolver for prefix "did:webplus:"
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait DIDResolver: Send + Sync + verifier_resolver::VerifierResolver {
    /// This resolves the given DID, returning the DID document, DID document metadata, and DID
    /// resolution metadata.  The metadata is needed for determining the validity duration of the
    /// latest DID document so as to be able to determine if a signing key was active at a given
    /// time.
    async fn resolve_did_document_string(
        &self,
        did_query: &str,
        did_resolution_options: DIDResolutionOptions,
    ) -> Result<(String, DIDDocumentMetadata, DIDResolutionMetadata)>;
    /// Convenience method.  This just calls into resolve_did_document_string and then deserializes
    /// the DID document string into a DIDDocument struct.
    async fn resolve_did_document(
        &self,
        did_query: &str,
        did_resolution_options: DIDResolutionOptions,
    ) -> Result<(DIDDocument, DIDDocumentMetadata, DIDResolutionMetadata)> {
        let (did_document_string, did_document_metadata, did_resolution_metadata) = self
            .resolve_did_document_string(did_query, did_resolution_options)
            .await?;
        let did_document: DIDDocument = serde_json::from_str(&did_document_string)
            .map_err(|e| Error::MalformedDIDDocument(e.to_string().into()))?;
        Ok((did_document, did_document_metadata, did_resolution_metadata))
    }
    /// Upcast to &dyn verifier_resolver::VerifierResolver.
    fn as_verifier_resolver(&self) -> &dyn verifier_resolver::VerifierResolver;
    /// Upcast to Arc<dyn verifier_resolver::VerifierResolver> by cloning.
    fn as_verifier_resolver_a(self: Arc<Self>) -> Arc<dyn verifier_resolver::VerifierResolver>;
}

/// Implementations of DIDResolver can use this to provide the guts to the implementation
/// of verifier_resolver::VerifierResolver.
pub async fn verifier_resolver_impl(
    verifier_str: &str,
    did_resolver: &dyn DIDResolver,
) -> verifier_resolver::Result<Box<dyn signature_dyn::VerifierDynT>> {
    if !verifier_str.starts_with("did:webplus:") {
        Err(verifier_resolver::Error::InvalidVerifier(
            format!(
                "expected verifier to begin with \"did:webplus:\", but verifier was {:?}",
                verifier_str
            )
            .into(),
        ))?;
    }

    tracing::debug!(
        "verifier was {:?}; verifying using did:webplus method",
        verifier_str
    );
    let did_key_resource_fully_qualified =
        did_webplus_core::DIDKeyResourceFullyQualifiedStr::new_ref(verifier_str).map_err(|_| verifier_resolver::Error::InvalidVerifier(format!("if did:webplus DID is used as verifier, it must be fully qualified, i.e. it must contain the selfHash and versionId query parameters and a fragment specifying the key ID, but it was {:?}", verifier_str).into()))?;

    let (did_document, _did_doc_metadata, _did_resolution_metadata) = did_resolver
        .resolve_did_document(
            did_key_resource_fully_qualified.without_fragment().as_str(),
            // did_webplus_core::RequestedDIDDocumentMetadata::none(),
            did_webplus_core::DIDResolutionOptions::default(),
        )
        .await?;

    // Retrieve the appropriate verifier from the DID document -- identified by the key_id_fragment.
    let verification_method = did_document
        .public_key_material
        .verification_method_for_key_id_fragment(did_key_resource_fully_qualified.fragment())?;
    // TODO: Go directly to the verifier bytes (maybe)
    let pub_key = mbx::MBPubKey::try_from(&verification_method.public_key_jwk)?;
    let verifier_bytes = signature_dyn::VerifierBytes::try_from(&pub_key)
        .map_err(|e| verifier_resolver::Error::InvalidVerifier(e.to_string().into()))?;
    Ok(Box::new(verifier_bytes))
}
