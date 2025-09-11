use crate::VDGAppState;
use axum::{
    extract::{Path, State},
    http::{
        header::{self, CACHE_CONTROL, ETAG, EXPIRES, LAST_MODIFIED},
        HeaderMap, HeaderValue, StatusCode,
    },
    routing::{get, post},
    Router,
};
use did_webplus_core::{DIDStr, DIDWithQueryStr, DID};
use time::{format_description::well_known, OffsetDateTime};
use tokio::task;

// Perhaps make this configurable?
const CACHE_DAYS: i64 = 365;

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
    tracing::debug!("VDG; fetch_did_documents_jsonl; did: {}", did);
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
    resolve_did_impl(&vdg_app_state, did.to_string()).await?;

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
            "retrieved entire did-documents.jsonl file in {:?}",
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
    tracing::trace!("VDG DID resolution; did_query: {}", did_query);

    let mut query_self_hash_o = None;
    let mut query_version_id_o = None;

    let did = if let Ok(did) = DIDStr::new_ref(did_query.as_str()) {
        tracing::trace!("got a plain DID to resolve, no query params: {}", did);
        did
    } else if let Ok(did_with_query) = DIDWithQueryStr::new_ref(did_query.as_str()) {
        tracing::trace!("got a DID with query params: {}", did_with_query);
        query_self_hash_o = did_with_query.query_self_hash_o();
        query_version_id_o = did_with_query.query_version_id_o();
        did_with_query.did()
    } else {
        return Err((StatusCode::BAD_REQUEST, "malformed DID query".to_string()));
    };

    use storage_traits::StorageDynT;
    let mut transaction_b = vdg_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // If either (or both) query param(s) are present, then it's possible it's already present in the
    // database and we can attempt to retrieve it.  Contrast with the no-query-params case, which requires
    // fetching the latest DID document from the VDR.
    if query_self_hash_o.is_some() || query_version_id_o.is_some() {
        tracing::trace!(
            "query param(s) present, attempting to retrieve DID document from database"
        );

        // There is a bit of a subtlety here, in that the query params, which act as filters on the
        // GET request, might conflict with the actual DID document.  I.e. one might ask for versionId=3
        // and selfHash=<hash> but the selfHash of version 3 might actually be different.  Thus we perform
        // the select only on one of the query params, and then check the other one after the fact.
        // versionId will be the primary filter (if present), and selfHash will be the secondary filter,
        // because versionId is more comprehensible for humans as having a particular location in the
        // DID microledger.
        let did_document_record_o = match (query_self_hash_o.as_deref(), query_version_id_o) {
            (Some(query_self_hash), None) => {
                // If only a selfHash is present, then we simply use it to select the DID document.
                vdg_app_state
                    .did_doc_store
                    .get_did_doc_record_with_self_hash(
                        Some(transaction_b.as_mut()),
                        &did,
                        query_self_hash,
                    )
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            }
            (query_self_hash_o, Some(query_version_id)) => {
                // If a versionId is present, then we can use it to select the DID document.
                let did_document_record_o = vdg_app_state
                    .did_doc_store
                    .get_did_doc_record_with_version_id(
                        Some(transaction_b.as_mut()),
                        &did,
                        query_version_id,
                    )
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                if let Some(query_self_hash) = query_self_hash_o {
                    if let Some(did_document_record) = did_document_record_o.as_ref() {
                        tracing::trace!("both selfHash and versionId query params present, so now a consistency check will be performed");
                        if did_document_record.self_hash.as_str() != query_self_hash.as_str() {
                            // Note: If there is a real signature by the DID which contains the conflicting
                            // selfHash and versionId values, then that represents a fork in the DID document,
                            // which is considered illegal and fraudulent.  However, simply receiving a request
                            // with conflicting selfHash and versionId values is not necessarily fraudulent, as
                            // it doesn't constitute proof that a signature was generated against a forked DID.
                            // Perhaps there could be a way to report a forked DID.
                            return Err((
                                StatusCode::UNPROCESSABLE_ENTITY,
                                format!(
                                    "DID document with versionId {} has selfHash {} which does not match the requested selfHash {}",
                                    query_version_id,
                                    did_document_record.self_hash,
                                    query_self_hash,
                                ),
                            ));
                        }
                    }
                }
                did_document_record_o
            }
            (None, None) => {
                unreachable!("programmer error");
            }
        };
        if let Some(did_document_record) = did_document_record_o {
            // If we do already have the requested DID document record, then we can return it.
            tracing::trace!(?did_query, "requested DID document already in database");
            transaction_b
                .commit()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            return Ok((
                headers_for_did_document(
                    did_document_record.self_hash.as_str(),
                    did_document_record.valid_from,
                    true,
                ),
                did_document_record.did_document_jcs,
            ));
        } else {
            tracing::trace!("requested DID document not in database");
        }
    }

    // Check what the latest version we do have is.
    tracing::trace!("checking latest DID document version in database");
    let latest_did_document_record_o = vdg_app_state
        .did_doc_store
        .get_latest_did_doc_record(Some(transaction_b.as_mut()), &did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(latest_did_document_record) = latest_did_document_record_o.as_ref() {
        tracing::trace!(
            "latest DID document version in database: {}",
            latest_did_document_record.version_id
        );
    } else {
        tracing::trace!("no DID documents in database for DID {}", did);
    }
    let latest_did_document_version_id_o = latest_did_document_record_o
        .as_ref()
        .map(|record| record.version_id as u32);
    // Compute 1 plus the latest version_id we have, or 0 if we have none.
    let version_id_start = if let Some(latest_did_document_record) =
        latest_did_document_record_o.as_ref()
    {
        (latest_did_document_record.version_id as u32)
            .checked_add(1).expect("programmer error: version_id overflow while incrementing latest version_id (this should be practically impossible)")
    } else {
        0
    };

    // Because we don't have the requested DID doc, we should fetch it and its predecessors from the VDR.
    let target_did_document_body = match (query_self_hash_o.as_ref(), query_version_id_o) {
        (Some(query_self_hash), _) => {
            // A DID doc with a specific selfHash value is being requested.  selfHash always overrides
            // versionId in terms of resolution.  Thus we have to fetch the selfHash-identified DID doc,
            // then all its predecessors.
            let did_with_query = did.with_query_self_hash(query_self_hash);
            tracing::trace!(
                "fetching DID document from VDR with selfHash value {}",
                query_self_hash
            );
            vdr_fetch_did_document_body(
                &did_with_query,
                vdg_app_state.http_scheme_override_o.as_ref(),
            )
            .await?
        }
        (None, Some(version_id)) => {
            // A DID doc with the specified versionId is being requested, but no selfHash is specified.
            // We can simply retrieve the precedessors sequentially up to the specified version.
            let did_with_query = did.with_query_version_id(version_id);
            tracing::trace!(
                "fetching DID document from VDR with versionId {}",
                version_id
            );
            vdr_fetch_did_document_body(
                &did_with_query,
                vdg_app_state.http_scheme_override_o.as_ref(),
            )
            .await?
        }
        (None, None) => {
            // The VDR's latest DID doc is being requested.  We must retrieve the latest version, then
            // all its predecessors.
            tracing::trace!("fetching latest DID document from VDR");
            vdr_fetch_latest_did_document_body(&did, vdg_app_state.http_scheme_override_o.as_ref())
                .await?
        }
    };
    let target_did_document = parse_did_document(&target_did_document_body)?;
    // Fetch predecessor DID docs from VDR.  TODO: Probably parallelize these requests with some max
    // on the number of simultaneous requests.
    let prev_did_document_body_o =
        latest_did_document_record_o.map(|record| record.did_document_jcs);
    let mut prev_did_document_o = prev_did_document_body_o.map(|prev_did_document_body| {
        parse_did_document(&prev_did_document_body)
            .expect("programmer error: stored DID document should be valid JSON")
    });
    for version_id in version_id_start..target_did_document.version_id {
        tracing::trace!(
            "fetching, validating, and storing predecessor DID document with versionId {}",
            version_id
        );
        let did_with_query = did.with_query_version_id(version_id);
        let predecessor_did_document_body = vdr_fetch_did_document_body(
            &did_with_query,
            vdg_app_state.http_scheme_override_o.as_ref(),
        )
        .await?;
        let predecessor_did_document = parse_did_document(&predecessor_did_document_body)?;
        vdg_app_state
            .did_doc_store
            .validate_and_add_did_doc(
                Some(transaction_b.as_mut()),
                &predecessor_did_document,
                prev_did_document_o.as_ref(),
                predecessor_did_document_body.as_str(),
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        prev_did_document_o = Some(predecessor_did_document);
    }
    // Finally, validate and store the target DID doc if necessary.
    // TODO: Need to handle forked DIDs eventually, but for now, this logic will use the first DID doc it
    // sees, which is precisely what should happen for a solo VDG (i.e. not part of a consensus cluster
    // of VDGs)
    if latest_did_document_version_id_o.is_none()
        || *latest_did_document_version_id_o.as_ref().unwrap() < target_did_document.version_id
    {
        tracing::trace!("validating and storing target DID document");
        vdg_app_state
            .did_doc_store
            .validate_and_add_did_doc(
                Some(transaction_b.as_mut()),
                &target_did_document,
                prev_did_document_o.as_ref(),
                &target_did_document_body,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // Now that we have fetched, validated, and stored the target DID doc and its predecessors,
    // we can check that the target DID doc matches the query param constraints and return it.
    if let Some(self_hash_str) = query_self_hash_o.as_deref() {
        use std::ops::Deref;
        if target_did_document.self_hash.deref() != self_hash_str {
            // Note: If there is a real signature by the DID which contains the conflicting selfHash and
            // versionId values, then that represents a fork in the DID document, which is considered
            // illegal and fraudulent.  However, simply receiving a request with conflicting selfHash and
            // versionId values is not necessarily fraudulent, as it doesn't constitute proof that a
            // signature was generated against a forked DID.  Perhaps there could be a way to report a
            // forked DID.
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "DID document with versionId {} has selfHash {} which does not match the requested selfHash {}",
                    target_did_document.version_id,
                    target_did_document.self_hash.deref(),
                    self_hash_str,
                ),
            ));
        }
    }
    if let Some(version_id) = query_version_id_o {
        if target_did_document.version_id != version_id {
            unreachable!("programmer error: this should not be possible");
        }
    }

    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::trace!(?did_query, "requested DID document was not already in database, so it had to be fetched from VDR; returning it now.");
    Ok((
        headers_for_did_document(
            target_did_document.self_hash.as_str(),
            target_did_document.valid_from(),
            false,
        ),
        target_did_document_body,
    ))
}

fn headers_for_did_document(
    hash: &str,
    last_modified: OffsetDateTime,
    cache_hit: bool,
) -> HeaderMap {
    let cache_control = format!("public, max-age={}, immutable", CACHE_DAYS * 24 * 60 * 60);
    let expires = OffsetDateTime::now_utc() + time::Duration::days(CACHE_DAYS);
    let expires_header = expires
        .format(&well_known::Rfc2822)
        .unwrap_or("".to_string());
    let last_modified_header = last_modified
        .format(&well_known::Rfc2822)
        .unwrap_or("".to_string());

    let mut headers = HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&cache_control).unwrap(),
    );
    headers.insert(EXPIRES, HeaderValue::from_str(&expires_header).unwrap());
    headers.insert(
        LAST_MODIFIED,
        HeaderValue::from_str(&last_modified_header).unwrap(),
    );
    headers.insert(ETAG, HeaderValue::from_str(hash).unwrap());
    headers.insert(
        "X-Cache-Hit",
        HeaderValue::from_static(if cache_hit { "true" } else { "false" }),
    );

    tracing::debug!("headers_for_did_document; headers: {:?}", headers);

    headers
}

async fn http_get(url: &str) -> Result<String, (StatusCode, String)> {
    tracing::trace!("VDG; http_get url: {}", url);
    // This is ridiculous.
    let response = crate::REQWEST_CLIENT
        .clone()
        .get(url)
        .send()
        .await
        .map_err(|err| {
            (
                err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                format!("error in HTTP request: {}", err),
            )
        })?;
    if response.status().is_success() {
        Ok(response.text().await.map_err(|err| {
            (
                err.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                format!("error in reading HTTP response body: {}", err),
            )
        })?)
    } else {
        Err((
            response.status(),
            "error in reading HTTP response body".to_string(),
        ))
    }
}

async fn vdr_fetch_latest_did_document_body(
    did: &DIDStr,
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
) -> Result<String, (StatusCode, String)> {
    http_get(did.resolution_url(http_scheme_override_o).as_str()).await
}

async fn vdr_fetch_did_document_body(
    did_with_query: &DIDWithQueryStr,
    http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
) -> Result<String, (StatusCode, String)> {
    http_get(
        did_with_query
            .resolution_url(http_scheme_override_o)
            .as_str(),
    )
    .await
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

fn parse_did_document(
    did_document_body: &str,
) -> Result<did_webplus_core::DIDDocument, (StatusCode, String)> {
    serde_json::from_str(did_document_body).map_err(|_| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "malformed DID document".to_string(),
        )
    })
}
