mod did_resolver;
mod did_resolver_full;
mod did_resolver_raw;
mod did_resolver_thin;
mod error;
mod http;

pub use crate::{
    did_resolver::DIDResolver,
    did_resolver_full::DIDResolverFull,
    did_resolver_raw::DIDResolverRaw,
    did_resolver_thin::DIDResolverThin,
    error::Error,
    http::{HTTPError, HTTPResult},
};
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) use crate::http::{
    vdr_fetch_did_document_body, vdr_fetch_latest_did_document_body, REQWEST_CLIENT,
};
