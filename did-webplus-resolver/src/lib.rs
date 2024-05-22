mod error;
mod http;
mod resolve_did;

pub use crate::{
    error::Error,
    http::{HTTPError, HTTPResult},
    resolve_did::resolve_did,
};
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) use crate::http::{vdr_fetch_did_document_body, vdr_fetch_latest_did_document_body};
