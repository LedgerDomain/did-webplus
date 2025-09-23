use crate::DIDResourceStr;

/// This will turn a did:key DIDResource into a Box<dyn signature_dyn::VerifierDynT>.
pub struct DIDKeyVerifierResolver;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl verifier_resolver::VerifierResolver for DIDKeyVerifierResolver {
    async fn resolve(
        &self,
        verifier_str: &str,
    ) -> verifier_resolver::Result<Box<dyn signature_dyn::VerifierDynT>> {
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
        let verifier_bytes = did_resource.did().to_verifier_bytes().into_owned();
        Ok(Box::new(verifier_bytes))
    }
}
