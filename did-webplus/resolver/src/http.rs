use did_webplus_core::{DIDStr, HTTPSchemeOverride};
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

pub async fn fetch_did_documents_jsonl_update(
    did: &DIDStr,
    vdg_base_url_o: Option<&url::Url>,
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    known_did_documents_jsonl_octet_length: u64,
) -> HTTPResult<String> {
    tracing::trace!(
        ?did,
        ?vdg_base_url_o,
        ?http_scheme_override_o,
        ?known_did_documents_jsonl_octet_length,
        "fetch_did_documents_jsonl_update"
    );

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
    let did_documents_jsonl_url = if let Some(vdg_base_url) = vdg_base_url_o {
        // Apply the http_scheme_override_o to the vdg_base_url.
        let http_scheme = HTTPSchemeOverride::determine_http_scheme_for_host_from(
            http_scheme_override_o,
            vdg_base_url.host_str().unwrap(),
        )
        .unwrap();
        let mut vdg_base_url = vdg_base_url.clone();
        vdg_base_url.set_scheme(http_scheme).unwrap();

        let mut did_documents_jsonl_url = vdg_base_url.clone();
        did_documents_jsonl_url
            .path_segments_mut()
            .unwrap()
            .push("webplus");
        did_documents_jsonl_url
            .path_segments_mut()
            .unwrap()
            .push("v1");
        did_documents_jsonl_url
            .path_segments_mut()
            .unwrap()
            .push("fetch");
        did_documents_jsonl_url
            .path_segments_mut()
            .unwrap()
            .push(did.as_str());
        did_documents_jsonl_url
            .path_segments_mut()
            .unwrap()
            .push("did-documents.jsonl");
        did_documents_jsonl_url.to_string()
    } else {
        did.resolution_url_for_did_documents_jsonl(http_scheme_override_o)
    };
    let did_documents_jsonl_update_r =
        http_get(did_documents_jsonl_url.as_str(), Some(header_map)).await;
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
