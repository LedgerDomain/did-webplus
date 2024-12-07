mod error;
mod verifier_resolver;
#[cfg(feature = "did-key-verifier-resolver")]
mod verifier_resolver_did_key;
#[cfg(feature = "did-webplus-verifier-resolver")]
mod verifier_resolver_did_webplus;
mod verifier_resolver_map;

#[cfg(feature = "did-key-verifier-resolver")]
pub use crate::verifier_resolver_did_key::VerifierResolverDIDKey;
#[cfg(feature = "did-webplus-verifier-resolver")]
pub use crate::verifier_resolver_did_webplus::VerifierResolverDIDWebplus;
pub use crate::{
    error::Error, verifier_resolver::VerifierResolver, verifier_resolver_map::VerifierResolverMap,
};

pub use anyhow::Result;
