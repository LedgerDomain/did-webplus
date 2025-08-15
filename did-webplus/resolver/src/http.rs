use did_webplus_core::{DIDStr, DIDWithQueryStr};
use reqwest::StatusCode;
use std::borrow::Cow;

lazy_static::lazy_static! {
    /// Building a reqwest::Client is *incredibly* slow, so we use a global instance and then clone
    /// it per use, as the documentation indicates.
    pub static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::new();
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

async fn http_get(
    url: &str,
    header_map_o: Option<reqwest::header::HeaderMap>,
) -> HTTPResult<String> {
    // This is ridiculous.
    let response = REQWEST_CLIENT
        .clone()
        .get(url)
        .headers(header_map_o.unwrap_or(reqwest::header::HeaderMap::new()))
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
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
) -> HTTPResult<String> {
    http_get(did.resolution_url(http_scheme_override_o).as_str(), None).await
}

// TODO: Add optional VDG to use as a proxy
pub async fn vdr_fetch_did_document_body(
    did_with_query: &DIDWithQueryStr,
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
) -> HTTPResult<String> {
    http_get(
        did_with_query
            .resolution_url(http_scheme_override_o)
            .as_str(),
        None,
    )
    .await
}

// TODO: Add optional VDG to use as a proxy
pub async fn vdr_fetch_did_documents_jsonl_update(
    did: &DIDStr,
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    known_did_documents_jsonl_octet_length: u64,
) -> HTTPResult<String> {
    let time_start = std::time::SystemTime::now();
    let header_map = {
        let mut header_map = reqwest::header::HeaderMap::new();
        header_map.insert(
            "Range",
            reqwest::header::HeaderValue::from_str(&format!(
                "bytes={}-",
                known_did_documents_jsonl_octet_length
            ))
            .unwrap(),
        );
        header_map
    };
    let did_documents_jsonl_update_r = http_get(
        did.resolution_url_for_did_documents_jsonl(http_scheme_override_o)
            .as_str(),
        Some(header_map),
    )
    .await;
    let duration = std::time::SystemTime::now()
        .duration_since(time_start)
        .expect("pass");
    if let Ok(did_documents_jsonl_update) = &did_documents_jsonl_update_r {
        tracing::info!(
            "Time taken to do a range-based GET of {} bytes of did-documents.jsonl starting at byte {}: {:?}",
            did_documents_jsonl_update.len(),
            known_did_documents_jsonl_octet_length,
            duration
        );
    }
    did_documents_jsonl_update_r
}
