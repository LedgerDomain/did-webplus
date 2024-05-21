use std::str::FromStr;

use axum::{
    extract::{Path, State},
    http::{
        header::{CACHE_CONTROL, ETAG, EXPIRES, LAST_MODIFIED},
        HeaderMap, HeaderValue, StatusCode,
    },
    routing::{get, post},
    Router,
};
use did_webplus::{DIDWithQuery, DID};
use sqlx::PgPool;
use time::{format_description::well_known, OffsetDateTime};
use tokio::task;

use crate::{models::did_document_record::DIDDocumentRecord, parse_did_document};

// Perhaps make this configurable?
const CACHE_DAYS: i64 = 365;
type DidResult = Result<(HeaderMap, String), (StatusCode, String)>;

pub fn get_routes(pool: &PgPool) -> Router {
    Router::new()
        .route("/:did_query", get(resolve_did))
        .route("/update/:did", post(update_did))
        .with_state(pool.clone())
}

#[tracing::instrument(err(Debug), skip(db))]
async fn resolve_did(
    State(db): State<PgPool>,
    // Note that did_query, which is expected to be a DID or a DIDWithQuery, is automatically URL-decoded by axum.
    Path(did_query): Path<String>,
) -> DidResult {
    tracing::trace!("starting DID resolution");

    let mut query_self_hash_o = None;
    let mut query_version_id_o = None;

    let did = if let Ok(did) = DID::from_str(did_query.as_str()) {
        tracing::trace!("got a plain DID to resolve, no query params: {}", did);
        did
    } else if let Ok(did_with_query) = DIDWithQuery::from_str(did_query.as_str()) {
        tracing::trace!("got a DID with query params: {}", did_with_query);
        query_self_hash_o = did_with_query.query_self_hash_o().map(|x| x.to_owned());
        query_version_id_o = did_with_query.query_version_id_o();
        did_with_query.without_query()
    } else {
        return Err((StatusCode::BAD_REQUEST, "malformed DID query".to_string()));
    };

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
            (Some(self_hash_str), None) => {
                // If only a selfHash is present, then we simply use it to select the DID document.
                DIDDocumentRecord::select_did_document(&db, &did, Some(self_hash_str), None).await?
            }
            (self_hash_str_o, Some(version_id)) => {
                // If a versionId is present, then we can use it to select the DID document.
                let did_document_record_o =
                    DIDDocumentRecord::select_did_document(&db, &did, None, Some(version_id))
                        .await?;
                if let Some(self_hash_str) = self_hash_str_o {
                    if let Some(did_document_record) = did_document_record_o.as_ref() {
                        tracing::trace!("both selfHash and versionId query params present, so now a consistency check will be performed");
                        if did_document_record.self_hash != self_hash_str {
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
                                    version_id,
                                    did_document_record.self_hash,
                                    self_hash_str,
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
            // If we do have the requested DID document record,  return it.
            tracing::trace!("requested DID document already in database");
            return Ok((
                headers_for_did_document(
                    did_document_record.self_hash,
                    did_document_record.valid_from,
                ),
                did_document_record.did_document,
            ));
        } else {
            tracing::trace!("requested DID document not in database");
        }
    }

    // Check what the latest version we do have is.
    tracing::trace!("checking latest DID document version in database");
    let latest_did_document_record_o = DIDDocumentRecord::select_latest(&db, &did).await?;
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
            let did_with_query = did.with_query_self_hash(query_self_hash.clone());
            tracing::trace!(
                "fetching DID document from VDR with selfHash value {}",
                query_self_hash
            );
            vdr_fetch_did_document_body(&did_with_query).await?
        }
        (None, Some(version_id)) => {
            // A DID doc with the specified versionId is being requested, but no selfHash is specified.
            // We can simply retrieve the precedessors sequentially up to the specified version.
            let did_with_query = did.with_query_version_id(version_id);
            tracing::trace!(
                "fetching DID document from VDR with versionId {}",
                version_id
            );
            vdr_fetch_did_document_body(&did_with_query).await?
        }
        (None, None) => {
            // The VDR's latest DID doc is being requested.  We must retrieve the latest version, then
            // all its predecessors.
            tracing::trace!("fetching latest DID document from VDR");
            vdr_fetch_latest_did_document_body(&did).await?
        }
    };
    let target_did_document = parse_did_document(&target_did_document_body)?;
    // Fetch predecessor DID docs from VDR.  TODO: Probably parallelize these requests with some max
    // on the number of simultaneous requests.
    let prev_did_document_body_o = latest_did_document_record_o.map(|record| record.did_document);
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
        let predecessor_did_document_body = vdr_fetch_did_document_body(&did_with_query).await?;
        let predecessor_did_document = parse_did_document(&predecessor_did_document_body)?;
        DIDDocumentRecord::append_did_document(
            &db,
            &predecessor_did_document,
            prev_did_document_o.as_ref(),
            predecessor_did_document_body.as_str(),
        )
        .await?;
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
        DIDDocumentRecord::append_did_document(
            &db,
            &target_did_document,
            prev_did_document_o.as_ref(),
            target_did_document_body.as_str(),
        )
        .await?;
    }

    // Now that we have fetched, validated, and stored the target DID doc and its predecessors,
    // we can check that the target DID doc matches the query param constraints and return it.
    if let Some(self_hash_str) = query_self_hash_o.as_deref() {
        use std::ops::Deref;
        if target_did_document.self_hash().deref() != self_hash_str {
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
                    target_did_document.self_hash().deref(),
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
    Ok((
        headers_for_did_document(
            target_did_document.self_hash().to_string(),
            target_did_document.valid_from(),
        ),
        target_did_document_body,
    ))
}

fn headers_for_did_document(hash: String, last_modified: OffsetDateTime) -> HeaderMap {
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
    headers.insert(ETAG, HeaderValue::from_str(&hash).unwrap());

    headers
}

async fn http_get(url: &str) -> Result<String, (StatusCode, String)> {
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

async fn vdr_fetch_latest_did_document_body(did: &DID) -> Result<String, (StatusCode, String)> {
    http_get(did.resolution_url().as_str()).await
}

async fn vdr_fetch_did_document_body(
    did_with_query: &DIDWithQuery,
) -> Result<String, (StatusCode, String)> {
    http_get(did_with_query.resolution_url().as_str()).await
}

#[tracing::instrument(err(Debug), skip(db))]
async fn update_did(
    State(db): State<PgPool>,
    Path(did): Path<String>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let did = match DID::from_str(did.as_str()) {
        Ok(did) => did,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "malformed DID".to_string())),
    };

    // Spawn a new task to handle the rest of the update since the vdr shouldn't need to wait
    // for the response as the vdg queries back the vdr for the latest did document
    let update_future = async move {
        let result = async {
            let did_document_body = vdr_fetch_latest_did_document_body(&did).await?;
            let did_document = parse_did_document(&did_document_body)?;
            DIDDocumentRecord::append_did_document(&db, &did_document, None, &did_document_body)
                .await?;
            Ok(())
        }
        .await;

        if let Err((_, err)) = result {
            tracing::error!("error updating DID document: {}", err);
        }
    };

    task::spawn(update_future);

    Ok((StatusCode::OK, "DID document update initiated".to_string()))
}
