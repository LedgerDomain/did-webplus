use crate::Result;

/// This trait provides a way to turn a "verifier" string into a Box<dyn selfsign::Verifier>.
/// For example, DID methods can implement this to turn a fully-qualified DID resource (that
/// specifies a specific pub key) into a Box<dyn selfsign::Verifier> of that public key.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait VerifierResolver: Send + Sync {
    async fn resolve(&self, verifier_str: &str) -> Result<Box<dyn selfsign::Verifier>>;
}
