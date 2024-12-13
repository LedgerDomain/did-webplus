use crate::{Error, Result, VerifierResolver};

/// This will turn a did:key DIDResource into a Box<dyn selfsign::Verifier>.
pub struct VerifierResolverDIDKey;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl VerifierResolver for VerifierResolverDIDKey {
    async fn resolve(&self, verifier_str: &str) -> Result<Box<dyn selfsign::Verifier>> {
        if !verifier_str.starts_with("did:key:") {
            anyhow::bail!(Error::InvalidVerifier(
                format!(
                    "expected verifier to begin with \"did:key:\", but verifier was {:?}",
                    verifier_str
                )
                .into(),
            ));
        }

        tracing::debug!(
            "verifier was {:?}; verifying using did:key method",
            verifier_str
        );
        tracing::debug!(
            "verifier was {:?}; verifying using did:key method",
            verifier_str
        );
        let did_resource = did_key::DIDResourceStr::new_ref(verifier_str).map_err(|e| {
            did_webplus_resolver::Error::InvalidVerifier(
                format!("invalid did:key value {:?}; error was: {}", verifier_str, e).into(),
            )
        })?;
        Ok(did_resource.did().to_verifier())
    }
}
