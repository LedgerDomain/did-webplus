use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use crate::test_vector_server_app_state::{
    TestVectorServerAppState, is_did_documents_jsonl, is_test_vector_json,
};

/// Build the HTTP router for the test-vector server (without `/health` or middleware).
pub fn get_routes(app_state: TestVectorServerAppState) -> Router {
    Router::new()
        .route("/index.json", get(get_index_json_root))
        .route("/{*path}", get(get_catch_all))
        .with_state(app_state)
}

#[tracing::instrument(level = tracing::Level::INFO, err(Debug), skip(app_state))]
async fn get_index_json_root(
    State(app_state): State<TestVectorServerAppState>,
) -> Result<Response, (StatusCode, String)> {
    // Convenience: always expose catalog index at `/index.json` when that is the
    // configured index path (empty `--did-path`). When `--did-path` is set, the
    // canonical index lives under the path prefix and is handled by the catch-all.
    if app_state.index_request_path.as_ref() == "index.json" {
        return Ok(json_response(
            StatusCode::OK,
            "application/json",
            app_state.index_json.as_ref(),
        ));
    }
    Err((
        StatusCode::NOT_FOUND,
        "index.json not at server root".to_string(),
    ))
}

#[tracing::instrument(level = tracing::Level::INFO, err(Debug), skip(app_state))]
async fn get_catch_all(
    State(app_state): State<TestVectorServerAppState>,
    Path(path): Path<String>,
    header_map: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    if path.as_str() == app_state.index_request_path.as_ref() {
        return Ok(json_response(
            StatusCode::OK,
            "application/json",
            app_state.index_json.as_ref(),
        ));
    }

    let Some((request_dir, filename)) = split_dir_and_filename(&path) else {
        return Err((StatusCode::NOT_FOUND, "not found".to_string()));
    };

    let Some(bodies) = app_state.vector_bodies(request_dir) else {
        return Err((StatusCode::NOT_FOUND, "vector not found".to_string()));
    };

    if is_did_documents_jsonl(filename) {
        return serve_did_documents_jsonl(&bodies.jsonl, &header_map);
    }
    if is_test_vector_json(filename) {
        return Ok(json_response(
            StatusCode::OK,
            "application/json",
            &bodies.test_vector_json,
        ));
    }

    Err((StatusCode::NOT_FOUND, "unknown file".to_string()))
}

fn split_dir_and_filename(path: &str) -> Option<(&str, &str)> {
    let (dir, filename) = path.rsplit_once('/')?;
    if dir.is_empty() || filename.is_empty() {
        return None;
    }
    Some((dir, filename))
}

fn json_response(status: StatusCode, content_type: &'static str, body: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    (status, headers, body.to_owned()).into_response()
}

/// Serve `did-documents.jsonl` with optional HTTP `Range` support.
///
/// Contract (resolver client):
/// - No `Range` → 200 full body, `Content-Type: application/jsonl`
/// - `Range: bytes={start}-` with `start < len` → 206 + `Content-Range: bytes {start}-{end}/{len}`
/// - `start == len` (or otherwise unsatisfiable at end) → 416 + `Content-Range: bytes */{len}`,
///   empty body, `Content-Length: 0`
fn serve_did_documents_jsonl(
    jsonl: &str,
    header_map: &HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let body_bytes = jsonl.as_bytes();
    let len = body_bytes.len() as u64;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/jsonl"),
    );

    let Some(range_header) = header_map.get(header::RANGE) else {
        return Ok((StatusCode::OK, response_headers, jsonl.to_owned()).into_response());
    };

    let range_header_str = range_header
        .to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid Range header".to_string()))?;
    if !range_header_str.starts_with("bytes=") {
        return Err((
            StatusCode::BAD_REQUEST,
            "Malformed Range header -- expected it to begin with 'bytes='".to_string(),
        ));
    }
    let range_header_str = range_header_str.strip_prefix("bytes=").unwrap();
    let (range_start_str, range_end_str) = range_header_str.split_once('-').ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Malformed Range header -- expected 'bytes=START-END'".to_string(),
        )
    })?;

    // Resolver sends `bytes={known}-` (open-ended). Reject exotic forms for MVP.
    if !range_end_str.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "only open-ended Range requests (bytes=START-) are supported".to_string(),
        ));
    }
    if range_start_str.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "suffix Range requests are not supported".to_string(),
        ));
    }
    let range_start: u64 = range_start_str.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Malformed Range header -- could not parse start".to_string(),
        )
    })?;

    if range_start > len {
        return Err((
            StatusCode::RANGE_NOT_SATISFIABLE,
            format!("Range start {range_start} exceeds content length {len}"),
        ));
    }

    if range_start == len {
        response_headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes */{len}")).unwrap(),
        );
        response_headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return Ok((
            StatusCode::RANGE_NOT_SATISFIABLE,
            response_headers,
            String::new(),
        )
            .into_response());
    }

    let start = range_start as usize;
    let end_inclusive = len - 1;
    let suffix = std::str::from_utf8(&body_bytes[start..])
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "jsonl is not UTF-8".to_string(),
            )
        })?
        .to_owned();

    response_headers.insert(
        header::CONTENT_RANGE,
        HeaderValue::from_str(&format!("bytes {range_start}-{end_inclusive}/{len}")).unwrap(),
    );

    Ok((StatusCode::PARTIAL_CONTENT, response_headers, suffix).into_response())
}
