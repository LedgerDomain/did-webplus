/// DIDWebplusVerifierResolver provides an implementation of VerifierResolver that loads the
/// DIDResolver lazily, which matters if loading the resolver involves opening a connection to
/// a database.
///
/// This will turn a did:webplus DIDResource[FullyQualified] into a Box<dyn signature_dyn::VerifierDynT>.
pub struct DIDWebplusVerifierResolver {
    pub did_resolver_factory_b: Box<dyn did_webplus_resolver::DIDResolverFactory>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl verifier_resolver::VerifierResolver for DIDWebplusVerifierResolver {
    async fn resolve(
        &self,
        verifier_str: &str,
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

        let did_resolver_b = self.did_resolver_factory_b.did_resolver().await?;
        let (did_document, _did_doc_metadata) = did_resolver_b
            .resolve_did_document(
                did_key_resource_fully_qualified.without_fragment().as_str(),
                did_webplus_core::RequestedDIDDocumentMetadata::none(),
            )
            .await?;

        // Retrieve the appropriate verifier from the DID document -- identified by the key_id_fragment.
        let verification_method = did_document
            .public_key_material
            .verification_method_for_key_id_fragment(did_key_resource_fully_qualified.fragment())?;
        // TODO: Convert directly to VerifierBytes instead of going through MBPubKey.
        let pub_key = mbx::MBPubKey::try_from(&verification_method.public_key_jwk)?;
        let verifier_bytes = signature_dyn::VerifierBytes::try_from(&pub_key)?;
        Ok(Box::new(verifier_bytes))
    }
}

unsafe impl Send for DIDWebplusVerifierResolver {}
unsafe impl Sync for DIDWebplusVerifierResolver {}
