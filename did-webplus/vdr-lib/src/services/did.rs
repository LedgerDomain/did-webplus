use crate::{VDRAppState, VDRConfig};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    routing::get,
    Router,
};
use did_webplus_core::{
    DIDDocumentMetadata, DIDDocumentMetadataConstant, DIDDocumentMetadataCurrency,
    DIDDocumentMetadataIdempotent, DIDWithQuery, DID,
};
use did_webplus_doc_store::DIDDocStore;
use tokio::task;

pub fn get_routes(did_doc_store: DIDDocStore, vdr_config: &VDRConfig) -> Router {
    let state = VDRAppState {
        did_doc_store,
        vdr_config: vdr_config.clone(),
    };

    Router::new()
        .route(
            // We have to do our own URL processing in each handler because of the non-standard
            // form of the "query" (e.g. did.selfHash=<hash>.json) and the fact that we're using
            // the same handler for multiple routes.
            "/{*path}",
            get(get_did).post(create_did).put(update_did),
        )
        .with_state(state)
}

#[tracing::instrument(level = tracing::Level::INFO, err(Debug), skip(vdr_app_state))]
async fn get_did(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
    header_map: HeaderMap,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    // Case for retrieving did-documents.jsonl (i.e. all DID docs concatenated into a single JSONL file)
    if let Ok(did) = DID::from_did_documents_jsonl_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    ) {
        return get_did_document_jsonl(State(vdr_app_state), header_map, did).await;
    }

    // Case for retrieving the latest DID doc.
    if let Ok(did) = DID::from_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    ) {
        return get_did_latest_did_document(State(vdr_app_state), header_map, did).await;
    }

    // Cases for retrieving a specific DID doc based on selfHash or versionId
    if let Ok(did_with_query) = DIDWithQuery::from_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    ) {
        return get_did_with_query(State(vdr_app_state), header_map, did_with_query).await;
    }

    // Cases for metadata
    if path.ends_with("/did/metadata.json") {
        return get_did_document_metadata(State(vdr_app_state), Path(path)).await;
    } else if path.ends_with("/did/metadata/constant.json") {
        return get_did_document_metadata_constant(State(vdr_app_state), Path(path)).await;
    } else if let Some((path, filename)) = path.rsplit_once('/') {
        return get_did_document_metadata_self_hash_or_version_id(
            State(vdr_app_state),
            path,
            filename,
        )
        .await;
    }

    // If none of the cases above matched, then the path is malformed.
    Err((StatusCode::BAD_REQUEST, "".to_string()))
}

// NOTE: This is duplicated in did-webplus-vdg-lib crate.  In order to de-duplicate, there would need to be
// an axum-aware crate common to this and that crate.
async fn get_did_document_jsonl(
    State(vdr_app_state): State<VDRAppState>,
    header_map: HeaderMap,
    did: DID,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!(
        ?did,
        "retrieving all DID docs concatenated into a single JSONL file; header_map: {:?}",
        header_map
    );

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
        let mut transaction_b = vdr_app_state
            .did_doc_store
            .begin_transaction()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let did_documents_jsonl_range = vdr_app_state
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
        let mut transaction_b = vdr_app_state
            .did_doc_store
            .begin_transaction()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let did_documents_jsonl = vdr_app_state
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

async fn get_did_latest_did_document(
    State(vdr_app_state): State<VDRAppState>,
    header_map: HeaderMap,
    did: DID,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!(
        ?did,
        "retrieving latest DID doc; header_map: {:?}",
        header_map
    );

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let latest_did_doc_record = vdr_app_state
        .did_doc_store
        .get_latest_did_doc_record(Some(transaction_b.as_mut()), &did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response_header_map = {
        let mut header_map = HeaderMap::new();
        header_map.insert("Content-Type", "application/json".parse().unwrap());
        header_map
    };
    return Ok((response_header_map, latest_did_doc_record.did_document_jcs));
}

async fn get_did_with_query(
    State(vdr_app_state): State<VDRAppState>,
    header_map: HeaderMap,
    did_with_query: DIDWithQuery,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!(
        ?did_with_query,
        "retrieving specific DID doc based on selfHash or versionId; header_map: {:?}",
        header_map
    );

    let did = did_with_query.did();
    let response_header_map = {
        let mut header_map = HeaderMap::new();
        header_map.insert("Content-Type", "application/json".parse().unwrap());
        header_map
    };

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(query_self_hash) = did_with_query.query_self_hash_o() {
        let did_doc_record = vdr_app_state
            .did_doc_store
            .get_did_doc_record_with_self_hash(Some(transaction_b.as_mut()), &did, query_self_hash)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok((response_header_map, did_doc_record.did_document_jcs));
    } else if let Some(query_version_id) = did_with_query.query_version_id_o() {
        let did_doc_record = vdr_app_state
            .did_doc_store
            .get_did_doc_record_with_version_id(
                Some(transaction_b.as_mut()),
                &did,
                query_version_id,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        transaction_b
            .commit()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok((response_header_map, did_doc_record.did_document_jcs));
    } else {
        return Err((StatusCode::BAD_REQUEST, "".to_string()));
    }
}

async fn get_did_document_metadata(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!("retrieving latest DID doc metadata");
    let path = path.strip_suffix("/did/metadata.json").unwrap();
    let did = DID::from_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path,
    )
    .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let latest_did_document_record = vdr_app_state
        .did_doc_store
        .get_latest_did_doc_record(Some(transaction_b.as_mut()), &did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
    let first_did_document_record = vdr_app_state
            .did_doc_store
            .get_did_doc_record_with_version_id(Some(transaction_b.as_mut()), &did, 0)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "if any DID doc is present in database for a DID, then its root DID doc (version 0) is expected to be present in database"
                        .to_string(),
                )
            })?;
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let current_did_document_metadata = DIDDocumentMetadata {
        constant_o: Some(DIDDocumentMetadataConstant {
            created: first_did_document_record.valid_from,
        }),
        idempotent_o: Some(DIDDocumentMetadataIdempotent {
            next_update_o: None,
            next_version_id_o: None,
        }),
        currency_o: Some(DIDDocumentMetadataCurrency {
            most_recent_update: latest_did_document_record.valid_from,
            most_recent_version_id: latest_did_document_record.version_id as u32,
        }),
    };

    let response_header_map = {
        let mut header_map = HeaderMap::new();
        header_map.insert("Content-Type", "application/json".parse().unwrap());
        header_map
    };
    let response_body = serde_json::to_string(&current_did_document_metadata).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize current DID document metadata into JSON".to_string(),
        )
    })?;
    return Ok((response_header_map, response_body));
}

async fn get_did_document_metadata_constant(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!("retrieving 'constant' DID doc metadata");
    let path = path.strip_suffix("/did/metadata/constant.json").unwrap();
    let did = DID::from_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path,
    )
    .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let first_did_document_record = vdr_app_state
        .did_doc_store
        .get_did_doc_record_with_version_id(Some(transaction_b.as_mut()), &did, 0)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let current_did_document_metadata = DIDDocumentMetadata {
        constant_o: Some(DIDDocumentMetadataConstant {
            created: first_did_document_record.valid_from,
        }),
        idempotent_o: None,
        currency_o: None,
    };

    let response_header_map = {
        let mut header_map = HeaderMap::new();
        header_map.insert("Content-Type", "application/json".parse().unwrap());
        header_map
    };
    let response_body = serde_json::to_string(&current_did_document_metadata).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize current DID document metadata into JSON".to_string(),
        )
    })?;
    return Ok((response_header_map, response_body));
}

async fn get_did_document_metadata_self_hash_or_version_id(
    State(vdr_app_state): State<VDRAppState>,
    path: &str,
    filename: &str,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!(
        ?path,
        ?filename,
        "retrieving 'selfHash' or 'versionId' DID doc metadata"
    );
    if !filename.ends_with(".json") {
        return Err((StatusCode::NOT_FOUND, "".to_string()));
    }

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (did, did_document_record) = if path.ends_with("/did/metadata/selfHash") {
        let path = path.strip_suffix("/did/metadata/selfHash").unwrap();
        let did = DID::from_resolution_url(
            vdr_app_state.vdr_config.did_hostname.as_str(),
            vdr_app_state.vdr_config.did_port_o,
            path,
        )
        .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let filename_self_hash_str = filename.strip_suffix(".json").unwrap();
        let filename_self_hash = mbc::MBHashStr::new_ref(filename_self_hash_str)
            .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let did_document_record = vdr_app_state
            .did_doc_store
            .get_did_doc_record_with_self_hash(
                Some(transaction_b.as_mut()),
                &did,
                filename_self_hash,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        (did, did_document_record)
    } else if path.ends_with("/did/metadata/versionId") {
        let path = path.strip_suffix("/did/metadata/versionId").unwrap();
        let did = DID::from_resolution_url(
            vdr_app_state.vdr_config.did_hostname.as_str(),
            vdr_app_state.vdr_config.did_port_o,
            path,
        )
        .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let filename_version_id_str = filename.strip_suffix(".json").unwrap();
        let filename_version_id: u32 = filename_version_id_str
            .parse()
            .map_err(|_| (StatusCode::BAD_REQUEST, "".to_string()))?;
        let did_document_record = vdr_app_state
            .did_doc_store
            .get_did_doc_record_with_version_id(
                Some(transaction_b.as_mut()),
                &did,
                filename_version_id,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "".to_string()))?;
        (did, did_document_record)
    } else {
        return Err((StatusCode::NOT_FOUND, "".to_string()));
    };
    let next_did_document_record_o = vdr_app_state
        .did_doc_store
        .get_did_doc_record_with_version_id(
            Some(transaction_b.as_mut()),
            &did,
            did_document_record.version_id as u32 + 1,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let first_did_document_record = vdr_app_state
            .did_doc_store
            .get_did_doc_record_with_version_id(Some(transaction_b.as_mut()), &did, 0)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "if any DID doc is present in database for a DID, then its root DID doc (version 0) is expected to be present in database"
                        .to_string(),
                )
            })?;
    let current_did_document_metadata = DIDDocumentMetadata {
        constant_o: Some(DIDDocumentMetadataConstant {
            created: first_did_document_record.valid_from,
        }),
        idempotent_o: Some(DIDDocumentMetadataIdempotent {
            next_update_o: next_did_document_record_o
                .as_ref()
                .map(|next_did_document_record| next_did_document_record.valid_from),
            next_version_id_o: next_did_document_record_o
                .as_ref()
                .map(|next_did_document_record| next_did_document_record.version_id as u32),
        }),
        currency_o: None,
    };
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let response_header_map = {
        let mut header_map = HeaderMap::new();
        header_map.insert("Content-Type", "application/json".parse().unwrap());
        header_map
    };
    let response_body = serde_json::to_string(&current_did_document_metadata).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to serialize current DID document metadata into JSON".to_string(),
        )
    })?;
    return Ok((response_header_map, response_body));
}

#[tracing::instrument(ret(Debug), err(Debug), skip(vdr_app_state, did_document_body))]
async fn create_did(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
    did_document_body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let did = DID::from_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    )
    .map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed DID resolution URL: {}", err),
        )
    })?;

    tracing::debug!(?did);
    tracing::trace!(
        "received request to create DID using DID document: {}",
        did_document_body
    );

    let root_did_document = parse_did_document(&did_document_body)?;
    if root_did_document.did != did {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "DID in document does not match the DID in the resolution URL: {} != {}",
                root_did_document.did, did
            ),
        ));
    }

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    vdr_app_state
        .did_doc_store
        .validate_and_add_did_doc(
            Some(transaction_b.as_mut()),
            &root_did_document,
            None,
            &did_document_body,
        )
        .await
        .map_err(|e| match e {
            did_webplus_doc_store::Error::AlreadyExists(_)
            | did_webplus_doc_store::Error::InvalidDIDDocument(_) => {
                (StatusCode::BAD_REQUEST, e.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
}

#[tracing::instrument(ret(Debug), err(Debug), skip(vdr_app_state, did_document_body))]
async fn update_did(
    State(vdr_app_state): State<VDRAppState>,
    Path(path): Path<String>,
    did_document_body: String,
) -> Result<(), (StatusCode, String)> {
    assert!(!path.starts_with('/'));

    let did = DID::from_resolution_url(
        vdr_app_state.vdr_config.did_hostname.as_str(),
        vdr_app_state.vdr_config.did_port_o,
        path.as_str(),
    )
    .map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("malformed DID resolution URL: {}", err),
        )
    })?;
    tracing::debug!(?path, ?did);

    use storage_traits::StorageDynT;
    let mut transaction_b = vdr_app_state
        .did_doc_store
        .begin_transaction()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let latest_did_document_record_o = vdr_app_state
        .did_doc_store
        .get_latest_did_doc_record(Some(transaction_b.as_mut()), &did)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if latest_did_document_record_o.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("DID does not exist: {}", did),
        ));
    }
    let latest_did_document_record = latest_did_document_record_o.unwrap();

    let new_did_document = parse_did_document(&did_document_body)?;
    if new_did_document.did != did {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "DID in document does not match the DID in the resolution URL: {} != {}",
                new_did_document.did, did
            ),
        ));
    }

    // TODO: Check if the previous did document is the root record if this will work. Otherwise add more logic.
    let prev_document =
        parse_did_document(&latest_did_document_record.did_document_jcs).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid DID document in storage".to_string(),
            )
        })?;

    vdr_app_state
        .did_doc_store
        .validate_and_add_did_doc(
            Some(transaction_b.as_mut()),
            &new_did_document,
            Some(&prev_document),
            &did_document_body,
        )
        .await
        .map_err(|e| match e {
            did_webplus_doc_store::Error::InvalidDIDDocument(_) => {
                (StatusCode::BAD_REQUEST, e.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;
    transaction_b
        .commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // TODO: Is there any reason to wait for this to complete, e.g. to ensure that all VDG updates succeeded?
    task::spawn(send_vdg_updates(
        vdr_app_state.vdr_config.vdg_base_url_v.clone(),
        did,
    ));

    Ok(())
}

lazy_static::lazy_static! {
    static ref VDG_CLIENT: reqwest::Client = reqwest::Client::new();
}

/// The reason this function takes its parameters by value instead of reference is because
/// it's called via task::spawn.  Note that errors here do not propagate back to the spawner,
/// and the client won't be aware that there was an error.  It's probably worth queue'ing these
/// updates and retrying them if they fail, with some retry schedule and eventually give up
/// after a certain number of retries, logging that fact.
#[tracing::instrument(level = tracing::Level::DEBUG, ret(Debug), err(Debug), skip(vdg_base_url_v))]
async fn send_vdg_updates(
    vdg_base_url_v: Vec<url::Url>,
    did: DID,
) -> anyhow::Result<Vec<(url::Url, reqwest::Result<reqwest::Response>)>> {
    tracing::trace!(?vdg_base_url_v, ?did, "VDR; send_vdg_updates");
    let mut join_set = tokio::task::JoinSet::new();
    for vdg_base_url in vdg_base_url_v.iter() {
        // Form the specific URL to POST to.
        let mut update_url = vdg_base_url.clone();
        update_url.path_segments_mut().unwrap().push("webplus");
        update_url.path_segments_mut().unwrap().push("v1");
        update_url.path_segments_mut().unwrap().push("update");
        // Note that `push` will percent-encode did_query!
        update_url.path_segments_mut().unwrap().push(did.as_str());
        tracing::info!("POST-ing update to VDG: {}", update_url);
        // There is no reason to do these sequentially, so spawn a task for each one.
        join_set.spawn(async move {
            let result = VDG_CLIENT
                .post(update_url.as_str())
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(
                        "error in POST-ing update to VDG: {}; error was: {}",
                        update_url,
                        err
                    );
                    err
                });
            (update_url, result)
        });
    }
    // Wait for all the tasks to complete, then return their results.
    Ok(join_set.join_all().await)
}

fn parse_did_document(
    did_document_body: &str,
) -> Result<did_webplus_core::DIDDocument, (axum::http::StatusCode, String)> {
    serde_json::from_str(did_document_body).map_err(|e| {
        tracing::error!(?e, "error parsing DID document");
        (
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            format!("malformed DID document: {}", e),
        )
    })
}
