mod did_resolver;
mod did_resolver_factory;
mod did_resolver_full;
mod did_resolver_thin;
mod error;
mod http;

pub use crate::{
    did_resolver::{DIDResolver, verifier_resolver_impl},
    did_resolver_factory::DIDResolverFactory,
    did_resolver_full::DIDResolverFull,
    did_resolver_thin::DIDResolverThin,
    error::Error,
    http::{HTTPError, HTTPResult},
};
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) use crate::http::{REQWEST_CLIENT, fetch_did_documents_jsonl_update};
