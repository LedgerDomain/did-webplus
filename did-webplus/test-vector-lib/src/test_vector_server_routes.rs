use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};

use crate::{
    RequestCountControlResponse, ServeCountControlRequest, ServeCountControlResponse,
    test_vector_server_app_state::{
        ServeCountError, TestVectorServerAppState, is_did_documents_jsonl,
        is_resolution_scenario_json, is_test_vector_json,
    },
};

/// Build the HTTP router for the test-vector server (without `/health` or middleware).
///
/// Includes catalog GETs and harness control endpoints outside the resolution namespace:
/// `PUT /control/serve-count`, `GET /control/request-count`, `POST /control/reset`.
pub fn get_routes(app_state: TestVectorServerAppState) -> Router {
    Router::new()
        .route("/index.json", get(get_index_json_root))
        .route("/control/serve-count", put(put_serve_count))
        .route("/control/request-count", get(get_request_count))
        .route("/control/reset", post(post_reset))
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

#[derive(Clone, Debug, serde::Deserialize)]
struct RequestCountQuery {
    path: String,
}

#[tracing::instrument(level = tracing::Level::INFO, err(Debug), skip(app_state))]
async fn put_serve_count(
    State(app_state): State<TestVectorServerAppState>,
    Json(request): Json<ServeCountControlRequest>,
) -> Result<Json<ServeCountControlResponse>, (StatusCode, String)> {
    let path = normalize_control_path(&request.path);
    match app_state.set_serve_count(path, request.served_did_document_count) {
        Ok((served_did_document_count, served_octet_length)) => {
            Ok(Json(ServeCountControlResponse {
                path: path.to_owned(),
                served_did_document_count,
                served_octet_length,
            }))
        }
        Err(ServeCountError::UnknownPath) => Err((
            StatusCode::NOT_FOUND,
            format!("vector path not found: {path}"),
        )),
        Err(error @ ServeCountError::CountExceedsDocuments { .. }) => {
            Err((StatusCode::BAD_REQUEST, error.to_string()))
        }
    }
}

#[tracing::instrument(level = tracing::Level::INFO, err(Debug), skip(app_state))]
async fn get_request_count(
    State(app_state): State<TestVectorServerAppState>,
    Query(query): Query<RequestCountQuery>,
) -> Result<Json<RequestCountControlResponse>, (StatusCode, String)> {
    let path = normalize_control_path(&query.path);
    let Some(request_count) = app_state.request_count(path) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("vector path not found: {path}"),
        ));
    };
    Ok(Json(RequestCountControlResponse {
        path: path.to_owned(),
        request_count,
    }))
}

#[tracing::instrument(level = tracing::Level::INFO, skip(app_state))]
async fn post_reset(State(app_state): State<TestVectorServerAppState>) -> StatusCode {
    app_state.reset_all();
    StatusCode::NO_CONTENT
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
        let Some(served_jsonl) = app_state.take_served_jsonl_for_request(request_dir) else {
            return Err((StatusCode::NOT_FOUND, "vector not found".to_string()));
        };
        return serve_did_documents_jsonl(served_jsonl, &header_map);
    }
    if is_test_vector_json(filename) {
        return Ok(json_response(
            StatusCode::OK,
            "application/json",
            &bodies.test_vector_json,
        ));
    }
    if is_resolution_scenario_json(filename) {
        let Some(scenario_json) = bodies.resolution_scenario_json_o.as_deref() else {
            return Err((
                StatusCode::NOT_FOUND,
                "resolution-scenario.json not present for this vector".to_string(),
            ));
        };
        return Ok(json_response(
            StatusCode::OK,
            "application/json",
            scenario_json,
        ));
    }

    Err((StatusCode::NOT_FOUND, "unknown file".to_string()))
}

fn normalize_control_path(path: &str) -> &str {
    path.strip_prefix('/').unwrap_or(path)
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
/// `jsonl` is the currently published prefix (possibly truncated by serve-count).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestVectorServerVectorBodies;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let mut body_m = HashMap::new();
        body_m.insert(
            "vec".to_owned(),
            TestVectorServerVectorBodies::new(
                "line0\nline1\nline2\n".to_owned(),
                "{\"name\":\"vec\"}\n".to_owned(),
                Some("{\"format\":\"did-webplus-resolution-scenario/1\"}\n".to_owned()),
            ),
        );
        let state = TestVectorServerAppState::from_parts(
            "{\"format\":\"did-webplus-test-vector-index/2\"}\n",
            "index.json",
            body_m,
        );
        get_routes(state)
    }

    async fn response_body_string(response: Response) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    #[tokio::test]
    async fn control_serve_count_truncates_jsonl_and_counts_requests() {
        let app = test_app();

        let put_response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri("/control/serve-count")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"path":"vec","servedDidDocumentCount":1}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("put");
        assert_eq!(put_response.status(), StatusCode::OK);
        let put_body = response_body_string(put_response).await;
        let put_json: ServeCountControlResponse =
            serde_json::from_str(&put_body).expect("parse put");
        assert_eq!(put_json.served_did_document_count, 1);
        assert_eq!(put_json.served_octet_length, 6);

        let get_jsonl = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/vec/did-documents.jsonl")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("get jsonl");
        assert_eq!(get_jsonl.status(), StatusCode::OK);
        assert_eq!(response_body_string(get_jsonl).await, "line0\n");

        let count_response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/control/request-count?path=vec")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("count");
        assert_eq!(count_response.status(), StatusCode::OK);
        let count_body = response_body_string(count_response).await;
        let count_json: RequestCountControlResponse =
            serde_json::from_str(&count_body).expect("parse count");
        assert_eq!(count_json.request_count, 1);

        let scenario = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/vec/resolution-scenario.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("scenario");
        assert_eq!(scenario.status(), StatusCode::OK);
        assert!(
            response_body_string(scenario)
                .await
                .contains("did-webplus-resolution-scenario/1")
        );

        let reset = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/control/reset")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("reset");
        assert_eq!(reset.status(), StatusCode::NO_CONTENT);

        let get_full = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/vec/did-documents.jsonl")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("get full");
        assert_eq!(
            response_body_string(get_full).await,
            "line0\nline1\nline2\n"
        );
    }
}
