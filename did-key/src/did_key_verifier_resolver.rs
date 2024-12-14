use crate::DIDResourceStr;

/// This will turn a did:key DIDResource into a Box<dyn selfsign::Verifier>.
pub struct DIDKeyVerifierResolver;

#[async_trait::async_trait]
impl verifier_resolver::VerifierResolver for DIDKeyVerifierResolver {
    async fn resolve(
        &self,
        verifier_str: &str,
    ) -> verifier_resolver::Result<Box<dyn selfsign::Verifier>> {
        if !verifier_str.starts_with("did:key:") {
            Err(verifier_resolver::Error::InvalidVerifier(
                format!(
                    "expected verifier to begin with \"did:key:\", but verifier was {:?}",
                    verifier_str
                )
                .into(),
            ))?;
        }

        tracing::debug!(
            "verifier was {:?}; verifying using did:key method",
            verifier_str
        );
        let did_resource = DIDResourceStr::new_ref(verifier_str).map_err(|e| {
            verifier_resolver::Error::InvalidVerifier(
                format!("invalid did:key value {:?}; error was: {}", verifier_str, e).into(),
            )
        })?;
        Ok(did_resource.did().to_verifier())
    }
}
