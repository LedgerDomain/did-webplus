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

pub(crate) const DID_KEY_ED25519_PREFIX: [u8; 2] = [0xed, 0x01];
pub(crate) const DID_KEY_SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];
pub(crate) const DID_KEY_BLS12381_G2_PREFIX: [u8; 2] = [0xeb, 0x01];
pub(crate) const DID_KEY_P256_PREFIX: [u8; 2] = [0x80, 0x24];
pub(crate) const DID_KEY_RSA_PREFIX: [u8; 2] = [0x85, 0x24];
