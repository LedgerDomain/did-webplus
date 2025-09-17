mod did;
#[cfg(feature = "verifier-resolver")]
mod did_key_verifier_resolver;
mod did_resource;
mod did_resource_str;
mod did_str;

#[cfg(feature = "verifier-resolver")]
pub use crate::did_key_verifier_resolver::DIDKeyVerifierResolver;
pub use crate::{
    did::DID, did_resource::DIDResource, did_resource_str::DIDResourceStr, did_str::DIDStr,
};
pub use anyhow::{Error, Result};
