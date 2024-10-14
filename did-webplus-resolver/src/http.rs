use did_webplus::{DIDStr, DIDWithQueryStr};
use reqwest::StatusCode;
use std::borrow::Cow;

lazy_static::lazy_static! {
    /// Building a reqwest::Client is *incredibly* slow, so we use a global instance and then clone
    /// it per use, as the documentation indicates.
    static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::new();
}

#[derive(Debug)]
pub struct HTTPError {
    pub status_code: reqwest::StatusCode,
    pub description: Cow<'static, str>,
}

impl std::fmt::Display for HTTPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type HTTPResult<T> = std::result::Result<T, HTTPError>;

async fn http_get(url: &str) -> HTTPResult<String> {
    // This is ridiculous.
    let response = REQWEST_CLIENT
        .clone()
        .get(url)
        .send()
        .await
        .map_err(|err| HTTPError {
            status_code: err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            description: format!("HTTP GET response was error: {}", err).into(),
        })?;
    if response.status().is_success() {
        Ok(response.text().await.map_err(|err| HTTPError {
            status_code: err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            description: format!("HTTP GET response body read error: {}", err).into(),
        })?)
    } else {
        Err(HTTPError {
            status_code: response.status(),
            description: "HTTP GET response body read error".into(),
        })
    }
}

// TODO: Add optional VDG to use as a proxy
pub async fn vdr_fetch_latest_did_document_body(
    did: &DIDStr,
    scheme: &'static str,
) -> HTTPResult<String> {
    http_get(did.resolution_url(scheme).as_str()).await
}

// TODO: Add optional VDG to use as a proxy
pub async fn vdr_fetch_did_document_body(
    did_with_query: &DIDWithQueryStr,
    scheme: &'static str,
) -> HTTPResult<String> {
    http_get(did_with_query.resolution_url(scheme).as_str()).await
}
