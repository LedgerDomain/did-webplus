use crate::VDGAppState;
use axum::{
    extract::{Path, State},
    http::{
        header::{self, CACHE_CONTROL, ETAG, LAST_MODIFIED},
        HeaderMap, HeaderValue, StatusCode,
    },
    routing::{get, post},
    Router,
};
use did_webplus_core::DID;
use did_webplus_resolver::DIDResolver;
use time::{format_description::well_known, OffsetDateTime};
use tokio::task;

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

    // Ensure that the VDG has the latest did-documents.jsonl file from the VDR.
    {
        let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
            vdg_app_state.did_doc_store.clone(),
            None,
            vdg_app_state.http_scheme_override_o.clone(),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        did_resolver_full
            .resolve_did_document_string(
                did.as_str(),
                did_webplus_core::RequestedDIDDocumentMetadata::none(),
            )
            .await
            .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    }

    let mut response_header_map = HeaderMap::new();
    response_header_map.insert("Content-Type", "application/jsonl".parse().unwrap());

    if let Some(range_header) = header_map.get(header::RANGE) {
        // Parse the "Range" header, if present, and then handle.

        let time_start = std::time::SystemTime::now();

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

        let duration = time_start.elapsed().unwrap();
        tracing::debug!(
            "retrieved range `{}` of did-documents.jsonl in {:?}",
            range_header_str,
            duration
        );

        return Ok((response_header_map, did_documents_jsonl_range));
    } else {
        // No Range header present, so serve the whole did-documents.jsonl file.

        let time_start = std::time::SystemTime::now();

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
        let duration = time_start.elapsed().unwrap();
        tracing::debug!(
            "retrieved entire did-documents.jsonl file ({} bytes) in {:?}",
            did_documents_jsonl.len(),
            duration
        );

        return Ok((response_header_map, did_documents_jsonl));
    }
}

#[tracing::instrument(err(Debug), skip(vdg_app_state))]
async fn resolve_did(
    State(vdg_app_state): State<VDGAppState>,
    // Note that did_query, which is expected to be a DID or a DIDWithQuery, is automatically URL-decoded by axum.
    Path(did_query): Path<String>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    resolve_did_impl(&vdg_app_state, did_query).await
}

async fn resolve_did_impl(
    vdg_app_state: &VDGAppState,
    did_query: String,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::trace!(?did_query, "VDG DID resolution");

    let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
        vdg_app_state.did_doc_store.clone(),
        None,
        vdg_app_state.http_scheme_override_o.clone(),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // TODO: Make this not require a transaction.
    use storage_traits::StorageDynT;
    let mut transaction_b = vdg_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (did_doc_record, was_resolved_locally) = did_resolver_full
        .resolve_did_doc_record(transaction_b.as_mut(), &did_query)
        .await
        .map_err(|e| match e {
            did_webplus_resolver::Error::DIDResolutionFailure(http_error) => {
                (http_error.status_code, http_error.description.into_owned())
            }
            did_webplus_resolver::Error::MalformedDIDQuery(description) => {
                (StatusCode::BAD_REQUEST, description.into_owned())
            }
            did_webplus_resolver::Error::FailedConstraint(description) => {
                (StatusCode::UNPROCESSABLE_ENTITY, description.into_owned())
            }
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        headers_for_did_documents_jsonl(
            did_doc_record.self_hash.as_str(),
            did_doc_record.valid_from,
            was_resolved_locally,
        ),
        did_doc_record.did_document_jcs,
    ))
}

fn headers_for_did_documents_jsonl(
    hash: &str,
    last_modified: OffsetDateTime,
    cache_hit: bool,
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
        "X-VDG-Cache-Hit",
        HeaderValue::from_static(if cache_hit { "true" } else { "false" }),
    );

    tracing::debug!("headers_for_did_document; headers: {:?}", headers);

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
            if let Err((_, err)) = resolve_did_impl(&vdg_app_state, did.to_string()).await {
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
