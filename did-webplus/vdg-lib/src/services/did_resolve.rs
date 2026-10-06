use crate::VDGAppState;
use axum::{
    Router,
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{self, CACHE_CONTROL, ETAG, LAST_MODIFIED},
    },
    routing::{get, post},
};
use did_webplus_core::{
    DID, DIDDocumentMetadata, DIDResolutionError, DIDResolutionMetadata, DIDResolutionOptions,
};
use did_webplus_resolver::DIDResolver;
use time::{OffsetDateTime, format_description::well_known};
use tokio::task;

/// HTTP 400 body: resolution metadata with `#INVALID_OPTIONS` and all locality booleans false.
fn invalid_options_response(detail: impl Into<String>) -> (StatusCode, String) {
    let did_resolution_metadata = DIDResolutionMetadata {
        content_type_o: None,
        error_o: Some(DIDResolutionError::invalid_options(detail)),
        fetched_updates_from_vdr: false,
        did_document_resolved_locally: false,
        did_document_metadata_resolved_locally: false,
    };
    (
        StatusCode::BAD_REQUEST,
        serde_json::to_string(&did_resolution_metadata).expect("serialize resolution metadata"),
    )
}

/// Parse a boolean DID-resolution-options header (`true` / `false` only).
fn parse_boolean_header(header_value: &HeaderValue) -> Result<bool, (StatusCode, String)> {
    let header_str = header_value
        .to_str()
        .map_err(|_| invalid_options_response("boolean header value is not valid ASCII"))?;
    header_str
        .parse::<bool>()
        .map_err(|_| invalid_options_response(format!("invalid boolean header value: {header_str}")))
}

/// Map a resolver error to HTTP status plus DID Resolution Metadata JSON body.
fn resolution_error_response(error: did_webplus_resolver::Error) -> (StatusCode, String) {
    let did_resolution_metadata = match error {
        did_webplus_resolver::Error::DIDResolutionFailure2(did_resolution_metadata)
        | did_webplus_resolver::Error::DIDResolutionConflict(did_resolution_metadata) => {
            did_resolution_metadata
        }
        other => DIDResolutionMetadata {
            content_type_o: None,
            error_o: Some(DIDResolutionError::internal_error(other.to_string())),
            fetched_updates_from_vdr: false,
            did_document_resolved_locally: false,
            did_document_metadata_resolved_locally: false,
        },
    };
    let status_code = did_resolution_metadata
        .error_o
        .as_ref()
        .map(|e| StatusCode::from_u16(e.http_status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status_code,
        serde_json::to_string(&did_resolution_metadata).expect("serialize resolution metadata"),
    )
}

pub fn get_routes(vdg_app_state: VDGAppState) -> Router {
    Router::new()
        .route(
            "/webplus/v1/fetch/{:did}/did-documents.jsonl",
            get(fetch_did_documents_jsonl),
        )
        .route("/webplus/v1/resolve/{:did_query}", get(resolve_did))
        .route("/webplus/v1/update/{:did}", post(update_did))
        .with_state(vdg_app_state)
}

#[tracing::instrument(err(Debug), skip(vdg_app_state))]
async fn fetch_did_documents_jsonl(
    State(vdg_app_state): State<VDGAppState>,
    header_map: HeaderMap,
    Path(did): Path<String>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!(?did, "VDG; fetch_did_documents_jsonl");
    // This should cause the VDG to fetch the latest from the VDR, then serve the did-documents.jsonl file.
    get_did_document_jsonl(
        State(vdg_app_state),
        header_map,
        DID::try_from(did).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
    )
    .await
}

// NOTE: This is duplicated in did-webplus-vdr-lib crate.  In order to de-duplicate, there would need to be
// an axum-aware crate common to this and that crate.
async fn get_did_document_jsonl(
    State(vdg_app_state): State<VDGAppState>,
    header_map: HeaderMap,
    did: DID,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!(
        ?did,
        "retrieving all DID docs concatenated into a single JSONL file; header_map: {:?}",
        header_map
    );

    vdg_app_state.verify_authorization(&header_map)?;

    // Ensure that the VDG has the latest did-documents.jsonl file from the VDR.
    {
        let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
            vdg_app_state.did_doc_store.clone(),
            None,
            Some(did_webplus_core::HTTPOptions {
                http_headers_for: vdg_app_state.vdg_config.http_headers_for.clone(),
                http_scheme_override: vdg_app_state.vdg_config.http_scheme_override.clone(),
            }),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        did_resolver_full
            .resolve_did_document_string(
                did.as_str(),
                did_webplus_core::DIDResolutionOptions::no_metadata(false),
            )
            .await
            .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    }

    let mut response_header_map = HeaderMap::new();
    response_header_map.insert("Content-Type", "application/jsonl".parse().unwrap());

    if let Some(range_header) = header_map.get(header::RANGE) {
        // Parse the "Range" header, if present, and then handle.

        let time_start = time::OffsetDateTime::now_utc();

        tracing::debug!("Range header: {:?}", range_header);
        let range_header_str = range_header.to_str().unwrap();
        if !range_header_str.starts_with("bytes=") {
            return Err((
                StatusCode::BAD_REQUEST,
                "Malformed Range header -- expected it to begin with 'bytes='".to_string(),
            ));
        }
        let range_header_str = range_header_str.strip_prefix("bytes=").unwrap();
        let (range_start_str, range_end_str) = range_header_str.split_once('-').unwrap();
        let range_begin_inclusive_o = if range_start_str.is_empty() {
            None
        } else {
            Some(range_start_str.parse::<u64>().unwrap())
        };
        let range_end_inclusive_o = if range_end_str.is_empty() {
            None
        } else {
            Some(range_end_str.parse::<u64>().unwrap())
        };
        let range_end_exclusive_o = range_end_inclusive_o.map(|x| x + 1);

        use storage_traits::StorageDynT;
        let mut transaction_b = vdg_app_state
            .did_doc_store
            .begin_transaction()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let did_documents_jsonl_range = vdg_app_state
            .did_doc_store
            .get_did_documents_jsonl_range(
                Some(transaction_b.as_mut()),
                &did,
                range_begin_inclusive_o,
                range_end_exclusive_o,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        response_header_map.insert(
            header::CONTENT_RANGE,
            format!(
                "bytes {}-{}/{}",
                range_start_str,
                range_end_str,
                did_documents_jsonl_range.len()
            )
            .parse()
            .unwrap(),
        );

        let duration = time::OffsetDateTime::now_utc() - time_start;
        tracing::debug!(
            "retrieved range `{}` of did-documents.jsonl in {:.3}",
            range_header_str,
            duration
        );

        return Ok((response_header_map, did_documents_jsonl_range));
    } else {
        // No Range header present, so serve the whole did-documents.jsonl file.

        let time_start = time::OffsetDateTime::now_utc();

        use storage_traits::StorageDynT;
        let mut transaction_b = vdg_app_state
            .did_doc_store
            .begin_transaction()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let did_documents_jsonl = vdg_app_state
            .did_doc_store
            .get_did_documents_jsonl_range(Some(transaction_b.as_mut()), &did, None, None)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let duration = time::OffsetDateTime::now_utc() - time_start;
        tracing::debug!(
            "retrieved entire did-documents.jsonl file ({} bytes) in {:.3}",
            did_documents_jsonl.len(),
            duration
        );

        return Ok((response_header_map, did_documents_jsonl));
    }
}

#[tracing::instrument(err(Debug), skip(vdg_app_state))]
async fn resolve_did(
    State(vdg_app_state): State<VDGAppState>,
    header_map: HeaderMap,
    // Note that did_query, which is expected to be a DID or a DIDWithQuery, is automatically URL-decoded by axum.
    Path(did_query): Path<String>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    vdg_app_state.verify_authorization(&header_map)?;
    resolve_did_impl(&vdg_app_state, Some(header_map), did_query).await
}

// TODO: Implement reading DIDResolutionOptions out of a header
async fn resolve_did_impl(
    vdg_app_state: &VDGAppState,
    header_map_o: Option<HeaderMap>,
    did_query: String,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::trace!(?did_query, "VDG DID resolution");

    let did_resolution_options = {
        let mut did_resolution_options = DIDResolutionOptions::default();
        if let Some(header_map) = header_map_o {
            if let Some(accept_header) = header_map.get(header::ACCEPT) {
                let accept_str = accept_header
                    .to_str()
                    .map_err(|_| invalid_options_response("Accept header value is not valid ASCII"))?;
                did_resolution_options.accept_o = Some(accept_str.to_string());
            }
            if let Some(request_creation_header) = header_map.get("X-DID-Request-Creation-Metadata")
            {
                did_resolution_options.request_creation =
                    parse_boolean_header(request_creation_header)?;
            }
            if let Some(request_next_header) = header_map.get("X-DID-Request-Next-Metadata") {
                did_resolution_options.request_next = parse_boolean_header(request_next_header)?;
            }
            if let Some(request_latest_header) = header_map.get("X-DID-Request-Latest-Metadata") {
                did_resolution_options.request_latest =
                    parse_boolean_header(request_latest_header)?;
            }
            if let Some(request_deactivated_header) =
                header_map.get("X-DID-Request-Deactivated-Metadata")
            {
                did_resolution_options.request_deactivated =
                    parse_boolean_header(request_deactivated_header)?;
            }
            if let Some(local_resolution_only_header) =
                header_map.get("X-DID-Local-Resolution-Only")
            {
                did_resolution_options.local_resolution_only =
                    parse_boolean_header(local_resolution_only_header)?;
            }
        }
        tracing::debug!(
            ?did_resolution_options,
            "did_resolution_options for VDG resolve request"
        );
        did_resolution_options
    };

    let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
        vdg_app_state.did_doc_store.clone(),
        None,
        Some(did_webplus_core::HTTPOptions {
            http_headers_for: vdg_app_state.vdg_config.http_headers_for.clone(),
            http_scheme_override: vdg_app_state.vdg_config.http_scheme_override.clone(),
        }),
    )
    .map_err(resolution_error_response)?;

    let (did_doc_record, did_document_metadata, mut did_resolution_metadata) = did_resolver_full
        .resolve_did_doc_record(&did_query, did_resolution_options)
        .await
        .map_err(resolution_error_response)?;

    // resolve_did_doc_record leaves contentType unset; VDG resolveRepresentation sets it here.
    did_resolution_metadata.content_type_o = Some("application/did+json".to_string());

    Ok((
        headers_for_did_documents_jsonl(
            did_doc_record.self_hash.as_str(),
            did_doc_record.valid_from,
            did_document_metadata,
            did_resolution_metadata,
        ),
        did_doc_record.did_document_jcs,
    ))
}

fn headers_for_did_documents_jsonl(
    hash: &str,
    last_modified: OffsetDateTime,
    did_document_metadata: DIDDocumentMetadata,
    did_resolution_metadata: DIDResolutionMetadata,
) -> HeaderMap {
    // See <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control>
    // - public: Allow storage in a shared cache.
    // - max-age=0 is a workaround for no-cache, because many old (HTTP/1.0) cache implementations
    //   don't support no-cache.
    // - no-cache: Correctness of DID resolution requires revalidation with VDR.
    // - no-transform: Don't transform the response, since did-documents.jsonl must be
    //   served exactly byte-for-byte.
    let cache_control = format!("public, max-age=0, no-cache, no-transform");
    let last_modified_header = last_modified
        .format(&well_known::Rfc2822)
        .unwrap_or("".to_string());

    let mut headers = HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&cache_control).unwrap(),
    );
    headers.insert(
        LAST_MODIFIED,
        HeaderValue::from_str(&last_modified_header).unwrap(),
    );
    headers.insert(ETAG, HeaderValue::from_str(hash).unwrap());
    headers.insert(
        "X-DID-Webplus-VDG-Cache-Hit",
        HeaderValue::from_static(if did_resolution_metadata.did_document_resolved_locally {
            "true"
        } else {
            "false"
        }),
    );
    headers.insert(
        "X-DID-Document-Metadata",
        HeaderValue::from_str(&serde_json::to_string(&did_document_metadata).unwrap()).unwrap(),
    );
    headers.insert(
        "X-DID-Resolution-Metadata",
        HeaderValue::from_str(&serde_json::to_string(&did_resolution_metadata).unwrap()).unwrap(),
    );

    tracing::trace!("headers_for_did_document; headers: {:?}", headers);

    headers
}

#[tracing::instrument(err(Debug), skip(vdg_app_state))]
async fn update_did(
    State(vdg_app_state): State<VDGAppState>,
    Path(did_string): Path<String>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    tracing::trace!("VDG; update_did; did_string: {}", did_string);
    let did = DID::try_from(did_string).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    tracing::trace!("VDG; update_did; did: {}", did);
    // Spawn a new task to handle the update since the vdr shouldn't need to wait
    // for the response as the vdg queries back the vdr for the latest did document
    task::spawn({
        async move {
            if let Err((_, err)) = resolve_did_impl(&vdg_app_state, None, did.to_string()).await {
                tracing::error!(
                    "error updating DID document for DID {} -- error was: {}",
                    did,
                    err
                );
            }
        }
    });

    Ok((StatusCode::OK, "DID document update initiated".to_string()))
}
