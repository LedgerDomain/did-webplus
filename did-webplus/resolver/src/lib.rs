mod did_resolver;
mod did_resolver_factory;
mod did_resolver_full;
mod did_resolver_raw;
mod did_resolver_thin;
mod error;
mod http;

pub use crate::{
    did_resolver::{verifier_resolver_impl, DIDResolver},
    did_resolver_factory::DIDResolverFactory,
    did_resolver_full::DIDResolverFull,
    did_resolver_raw::DIDResolverRaw,
    did_resolver_thin::DIDResolverThin,
    error::Error,
    http::{HTTPError, HTTPResult},
};
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) use crate::http::{fetch_did_documents_jsonl_update, REQWEST_CLIENT};
