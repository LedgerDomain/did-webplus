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

/// This is used to fetch updates to the DID document JSONL file.  Notably, it will accept
/// HTTP 206 and conditionally accept 416 if the Content-Range header indicates that the
/// content size is the same as the known length of the did-documents.jsonl file.
async fn http_get_range_bytes(
    did: &DIDStr,
    url: &str,
    known_did_documents_jsonl_octet_length: u64,
) -> HTTPResult<String> {
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
    // This is ridiculous.
    let response = REQWEST_CLIENT
        .clone()
        .get(url)
        .headers(header_map)
        .send()
        .await
        .map_err(|err| HTTPError {
            status_code: err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            description: format!("HTTP GET response was error: {}", err).into(),
        })?;
    if response.status().is_success() {
        return Ok(response.text().await.map_err(|err| HTTPError {
            status_code: err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            description: format!("HTTP GET response body read error: {}", err).into(),
        })?);
    }

    if response.status() == StatusCode::RANGE_NOT_SATISFIABLE {
        tracing::trace!(
            "HTTP GET response status is RANGE_NOT_SATISFIABLE -- checking for Content-Range header"
        );
        if let Some(content_range) = response.headers().get("Content-Range") {
            tracing::trace!(
                "HTTP GET response Content-Range header: {:?}",
                content_range
            );
            let content_range_str = content_range.to_str().unwrap();
            if !content_range_str.starts_with("bytes */") {
                return Err(HTTPError {
                    status_code: response.status(),
                    description: format!(
                        "HTTP GET response Content-Range header is not valid: {}",
                        content_range_str
                    )
                    .into(),
                });
            }
            use std::str::FromStr;
            let content_size = u64::from_str(content_range_str.strip_prefix("bytes */").unwrap())
                .or_else(|e| {
                Err(HTTPError {
                    status_code: response.status(),
                    description: format!(
                        "Failed to parse Content-Range header {:?}; error: {}",
                        content_range_str, e
                    )
                    .into(),
                })
            })?;
            debug_assert!(response.headers().get("Content-Length").is_some());
            debug_assert!(matches!(
                response.headers().get("Content-Length").unwrap().to_str(),
                Ok("0")
            ));
            if content_size == known_did_documents_jsonl_octet_length {
                // 0 bytes were returned and the returned content-length matches the known length,
                // so the DID document is up to date.
                return Ok(String::new());
            } else {
                return Err(HTTPError {
                    status_code: response.status(),
                    description: format!(
                        "HTTP GET response Content-Range indicated a size {} that does not match the known length {} of did-documents.jsonl for {}",
                        content_size,
                        known_did_documents_jsonl_octet_length,
                        did,
                    ).into(),
                });
            }
        }
    }
    Err(HTTPError {
        status_code: response.status(),
        description: "HTTP GET response body read error (generic)".into(),
    })
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
    let did_documents_jsonl_update_r = http_get_range_bytes(
        did,
        did_documents_jsonl_url.as_str(),
        known_did_documents_jsonl_octet_length,
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
