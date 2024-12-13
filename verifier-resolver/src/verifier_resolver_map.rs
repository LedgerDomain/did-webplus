use crate::{Error, Result, VerifierResolver};
use std::collections::HashMap;

/// This provides a VerifierResolver impl which can resolve many different types of verifiers,
/// each with their own prefix.  The prefix is used to classify the verifier and determine which
/// specifiec VerifierResolver to use to resolve it.
pub struct VerifierResolverMap {
    verifier_prefix_v: Vec<String>,
    verifier_resolver_m: HashMap<String, Box<dyn VerifierResolver>>,
}

impl VerifierResolverMap {
    pub fn new() -> Self {
        Self {
            verifier_prefix_v: Vec::new(),
            verifier_resolver_m: HashMap::new(),
        }
    }
    pub fn with(
        mut self,
        verifier_prefix: &str,
        verifier_resolver_b: Box<dyn VerifierResolver>,
    ) -> Self {
        self.verifier_prefix_v.push(verifier_prefix.to_owned());
        self.verifier_resolver_m
            .insert(verifier_prefix.to_owned(), verifier_resolver_b);
        self
    }
    pub fn classify_verifier(&self, verifier_str: &str) -> Result<&str> {
        for verifier_prefix in self.verifier_prefix_v.iter() {
            if verifier_str.starts_with(verifier_prefix) {
                return Ok(verifier_prefix);
            }
        }
        anyhow::bail!(Error::UnsupportedVerifier(verifier_str.to_owned().into()));
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl VerifierResolver for VerifierResolverMap {
    async fn resolve(&self, verifier_str: &str) -> Result<Box<dyn selfsign::Verifier>> {
        let verifier_class = self.classify_verifier(verifier_str)?;
        if let Some(verifier_resolver) = self.verifier_resolver_m.get(verifier_class) {
            Ok(verifier_resolver.resolve(verifier_str).await?)
        } else {
            anyhow::bail!(Error::UnsupportedVerifier(verifier_str.to_owned().into()));
        }
    }
}
