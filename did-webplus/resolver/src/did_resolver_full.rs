#![allow(unused)]

use crate::{DIDResolver, Error, Result, fetch_did_documents_jsonl_update, verifier_resolver_impl};
use did_webplus_core::{
    CreationMetadata, DIDDocumentMetadata, DIDResolutionMetadata, DIDResolutionOptions, DIDStr,
    DIDURIComponents, DIDWithQueryStr, LatestUpdateMetadata, NextUpdateMetadata,
    RootLevelUpdateRules, UpdatesDisallowed,
};
use did_webplus_doc_store::{DIDDocRecord, parse_did_document};
use std::sync::Arc;

/// This is the "full" implementation of a DID resolver, which which keeps a local copy of all DID
/// documents it has fetched and verified.  This is in contrast to the "thin" implementation, which
/// outsources the retrieval and verification of DID documents to a trusted Verifiable Data Gateway (VDG).
/// A VDG can optionally be specified to forward resolution requests through, though DID documents will
/// still be locally verified and stored.  The reason for this is to ensure a broader scope-of-truth
/// for which DID updates are considered valid (all resolvers which use the specified VDG will agree).
#[derive(Clone)]
pub struct DIDResolverFull {
    did_doc_store: did_webplus_doc_store::DIDDocStore,
    /// Optionally specifies the "base" URL of a VDG to use for fetching DID documents.  This is used
    /// so that this resolver can take part in the scope of agreement defined by the VDG.  Without
    /// using a VDG, a DIDResolverFull has a scope of agreement that only contains itself.
    vdg_base_url_o: Option<url::Url>,
    http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
}

impl DIDResolverFull {
    pub fn new(
        did_doc_store: did_webplus_doc_store::DIDDocStore,
        vdg_host_o: Option<&str>,
        http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<Self> {
        let vdg_base_url_o = if let Some(vdg_host) = vdg_host_o {
            let http_scheme =
                did_webplus_core::HTTPSchemeOverride::default_http_scheme_for_host(vdg_host)
                    .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
            let vdg_base_url = url::Url::parse(&format!("{}://{}", http_scheme, vdg_host))
                .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
            Some(vdg_base_url)
        } else {
            None
        };
        Ok(Self {
            did_doc_store,
            vdg_base_url_o,
            http_scheme_override_o,
        })
    }
    /// Note that this doesn't use a transaction, because the did-documents.jsonl data is append-only,
    /// so adding valid DID documents is an idempotent operation.
    pub async fn resolve_did_doc_record(
        &self,
        did_query: &str,
        did_resolution_options: DIDResolutionOptions,
    ) -> Result<(DIDDocRecord, DIDDocumentMetadata, DIDResolutionMetadata)> {
        tracing::trace!("starting DID resolution");

        let mut query_self_hash_o = None;
        let mut query_version_id_o = None;

        // Determine which case we're handling; a DID with or without query params.
        let did_uri_components = DIDURIComponents::try_from(did_query)
            .map_err(|err| Error::MalformedDIDQuery(err.to_string().into()))?;
        tracing::trace!("did_uri_components: {:?}", did_uri_components);
        if did_uri_components.has_fragment() {
            return Err(Error::MalformedDIDQuery(
                "DID query contains a fragment (this is not (yet?) supported)".into(),
            ));
        }
        let did = if !did_uri_components.has_query() {
            tracing::trace!("got a plain DID to resolve, no query params: {}", did_query);
            DIDStr::new_ref(did_query)
                .map_err(|err| Error::MalformedDIDQuery(err.to_string().into()))?
        } else {
            tracing::trace!("got a DID with query params: {}", did_query);
            let did_with_query = DIDWithQueryStr::new_ref(did_query)
                .map_err(|err| Error::MalformedDIDQuery(err.to_string().into()))?;
            query_self_hash_o = did_with_query.query_self_hash_o();
            query_version_id_o = did_with_query.query_version_id_o();
            did_with_query.did()
        };
        tracing::trace!("DID: {:?}", did);

        // Note to the poor reader: This function is long and messy mostly because of how
        // the DIDDocumentMetadata has to be determined.  If no DIDDocumentMetadata is requested,
        // then a majority of this is skipped.

        // First, determine which DID documents we need in order to provide all requested data and metadata:
        let root_did_document_needed = did_resolution_options.request_creation;
        let requested_did_document_needed = true;
        let next_did_document_o_needed = did_resolution_options.request_next;
        let latest_did_document_needed =
            did_resolution_options.request_latest || did_resolution_options.request_deactivated;

        // Now attempt to retrieve all the needed DID documents locally.
        let mut root_did_doc_record_o = None;
        let mut requested_did_doc_record_o = None;
        let mut next_did_doc_record_oo: Option<Option<DIDDocRecord>> = None;
        let mut latest_did_doc_record_o = None;
        if root_did_document_needed {
            tracing::trace!(
                ?root_did_document_needed,
                ?did,
                "attempting to retrieve root DID document from local DB"
            );
            root_did_doc_record_o = self
                .did_doc_store
                .get_did_doc_record_with_version_id(None, did, 0)
                .await?;
            tracing::trace!(?root_did_doc_record_o, "root DID document local DB result");
        }
        if requested_did_document_needed {
            tracing::trace!(
                ?requested_did_document_needed,
                ?did,
                "attempting to retrieve requested DID document from local DB"
            );
            if query_self_hash_o.is_some() || query_version_id_o.is_some() {
                tracing::trace!(
                    ?query_self_hash_o,
                    ?query_version_id_o,
                    "attempting to retrieve requested DID document from local DB with query params"
                );
                requested_did_doc_record_o = self
                    .get_did_doc_record_with_self_hash_or_version_id(
                        None,
                        did,
                        query_self_hash_o,
                        query_version_id_o,
                    )
                    .await?;
                tracing::trace!(
                    ?requested_did_doc_record_o,
                    "requested DID document local DB result"
                );
                if let Some(requested_did_doc_record) = requested_did_doc_record_o.as_ref() {
                    let requested_did_document =
                        parse_did_document(&requested_did_doc_record.did_document_jcs)?;
                    if requested_did_document.is_deactivated() {
                        tracing::trace!(
                            ?requested_did_document,
                            "requested DID document is deactivated, thus it's the latest, and there is no next DID document"
                        );
                        // If the requested DID document is deactivated, then by construction it's the latest.
                        latest_did_doc_record_o = Some(requested_did_doc_record.clone());
                        // And we now positively know that there is no next DID document.
                        next_did_doc_record_oo = Some(None);
                    }
                }
            } else {
                tracing::trace!("attempting to retrieve latest known DID document from local DB");
                let latest_known_did_doc_record_o = self
                    .did_doc_store
                    .get_latest_known_did_doc_record(None, did)
                    .await?;
                tracing::trace!(
                    ?latest_known_did_doc_record_o,
                    "latest known DID document local DB result"
                );
                if let Some(latest_known_did_doc_record) = latest_known_did_doc_record_o {
                    let latest_known_did_document =
                        parse_did_document(&latest_known_did_doc_record.did_document_jcs)?;
                    if latest_known_did_document.is_deactivated() {
                        tracing::trace!(
                            ?latest_known_did_document,
                            "latest known DID document is deactivated, thus it's the latest, and the requested DID document is the latest known one, and there is no next DID document"
                        );
                        // If the latest known DID document is deactivated, then by construction it's the latest.
                        latest_did_doc_record_o = Some(latest_known_did_doc_record.clone());
                        // And we know that the latest known DID document is the requested one.
                        requested_did_doc_record_o = Some(latest_known_did_doc_record.clone());
                        // And we now positively know that there is no next DID document.
                        next_did_doc_record_oo = Some(None);
                    }
                }
            }
        } else {
            unreachable!();
        }
        if next_did_document_o_needed
            && requested_did_doc_record_o.is_some()
            && next_did_doc_record_oo.is_none()
        {
            tracing::trace!(
                ?next_did_document_o_needed,
                ?requested_did_doc_record_o,
                ?next_did_doc_record_oo,
                "attempting to retrieve next DID document from local DB"
            );
            // Attempt to retrieve the next DID document.  This is only well-defined if we already were
            // able to retrieve the requested DID document.
            let requested_did_document = parse_did_document(
                &requested_did_doc_record_o
                    .as_ref()
                    .unwrap()
                    .did_document_jcs,
            )?;
            let requested_did_document_version_id = u32::try_from(requested_did_document.version_id).expect("version_id overflow; this is so unlikely that it's almost certainly a programmer error");
            let next_did_document_version_id = requested_did_document_version_id.checked_add(1).expect("version_id overflow; this is so unlikely that it's almost certainly a programmer error");
            tracing::trace!(
                ?requested_did_document_version_id,
                ?next_did_document_version_id,
            );
            let next_did_doc_record_o = self
                .did_doc_store
                .get_did_doc_record_with_version_id(None, did, next_did_document_version_id)
                .await?;
            tracing::trace!(?next_did_doc_record_o, "next DID document local DB result");
            if next_did_doc_record_o.is_some() {
                // Only set next_did_doc_record_oo if we actually found a next DID document.
                next_did_doc_record_oo = Some(next_did_doc_record_o);
            }
        }
        if latest_did_document_needed && latest_did_doc_record_o.is_none() {
            tracing::trace!("attempting to retrieve latest DID document from local DB");
            if let Some(latest_known_did_doc_record) = self
                .did_doc_store
                .get_latest_known_did_doc_record(None, did)
                .await?
            {
                tracing::trace!(
                    ?latest_known_did_doc_record,
                    "latest known DID document local DB result"
                );
                let latest_known_did_document =
                    parse_did_document(&latest_known_did_doc_record.did_document_jcs)?;
                if latest_known_did_document.is_deactivated() {
                    tracing::trace!(
                        ?latest_known_did_document,
                        "latest known DID document is deactivated, thus it's the latest, and the requested DID document is the latest known one, and there is no next DID document"
                    );
                    // If the latest known DID document is deactivated, then by construction it's the latest.
                    latest_did_doc_record_o = Some(latest_known_did_doc_record.clone());
                    // And we know that the latest known DID document is the requested one.
                    if requested_did_doc_record_o.is_none() {
                        requested_did_doc_record_o = Some(latest_known_did_doc_record.clone());
                    }
                    // And we now positively know that there is no next DID document.
                    if next_did_doc_record_oo.is_none() {
                        next_did_doc_record_oo = Some(None);
                    }
                }
            }
        }

        tracing::trace!(
            "results from attempting to assemble needed data for local resolution:\n    root_did_document_needed: {}\n    root_did_doc_record_o.is_some(): {:?}\n    requested_did_document_needed: {}\n    requested_did_doc_record_o.is_some(): {:?}\n    next_did_document_o_needed: {}\n    next_did_doc_record_oo.is_some(): {:?}\n    latest_did_document_needed: {}\n    latest_did_doc_record_o.is_some(): {:?}",
            root_did_document_needed,
            root_did_doc_record_o.is_some(),
            requested_did_document_needed,
            requested_did_doc_record_o.is_some(),
            next_did_document_o_needed,
            next_did_doc_record_oo.is_some(),
            latest_did_document_needed,
            latest_did_doc_record_o.is_some(),
        );

        // Determine if the requested DID document was resolved locally.
        let did_document_resolved_locally = requested_did_doc_record_o.is_some();
        let did_document_metadata_resolved_locally = (!root_did_document_needed
            || root_did_doc_record_o.is_some())
            && (!next_did_document_o_needed || next_did_doc_record_oo.is_some())
            && (!latest_did_document_needed || latest_did_doc_record_o.is_some());
        tracing::trace!(
            ?did_document_resolved_locally,
            ?did_document_metadata_resolved_locally
        );

        // Determine if we need to fetch updates from the VDR in order to fulfill the request.
        let mut fetched_updates_from_vdr = false;
        if (root_did_document_needed && root_did_doc_record_o.is_none())
            || (requested_did_document_needed && requested_did_doc_record_o.is_none())
            || (next_did_document_o_needed && next_did_doc_record_oo.is_none())
            || (latest_did_document_needed && latest_did_doc_record_o.is_none())
        {
            tracing::trace!("fetching updates from VDR is needed to fulfill the request");
            if did_resolution_options.local_resolution_only {
                tracing::trace!(
                    "local-only DID resolution for {} was not able to complete",
                    did,
                );
                return Err(Error::DIDResolutionFailure2(DIDResolutionMetadata {
                    content_type: "application/did+json".to_string(),
                    error_o: Some(format!(
                        "local-only DID resolution for {} was not able to complete",
                        did
                    )),
                    fetched_updates_from_vdr,
                    did_document_resolved_locally,
                    did_document_metadata_resolved_locally,
                }));
            }
            self.fetch_validate_and_store_did_updates_from_vdr(did)
                .await?;
            fetched_updates_from_vdr = true;
            tracing::trace!(?fetched_updates_from_vdr);

            // Now that updates have been fetched from the VDR, make sure that the needed data is present.
            if root_did_document_needed && root_did_doc_record_o.is_none() {
                tracing::trace!("attempting to retrieve root DID document after VDR fetch");
                let root_did_doc_record = self
                    .did_doc_store
                    .get_did_doc_record_with_version_id(None, did, 0)
                    .await?
                    .ok_or_else(|| {
                        Error::DIDResolutionFailure2(DIDResolutionMetadata {
                            content_type: "application/did+json".to_string(),
                            error_o: Some(format!("DID resolution for {} failed (root DID document resolution failed)", did)),
                            fetched_updates_from_vdr,
                            did_document_resolved_locally,
                            did_document_metadata_resolved_locally,
                        })
                    })?;
                tracing::trace!(?root_did_doc_record, "root DID document local DB result");
                root_did_doc_record_o = Some(root_did_doc_record);
            }
            if requested_did_document_needed && requested_did_doc_record_o.is_none() {
                tracing::trace!("attempting to retrieve requested DID document after VDR fetch");
                if query_self_hash_o.is_some() || query_version_id_o.is_some() {
                    tracing::trace!(
                        ?query_self_hash_o,
                        ?query_version_id_o,
                        "attempting to retrieve requested DID document from local DB with query params after VDR fetch"
                    );
                    let requested_did_doc_record = self
                        .get_did_doc_record_with_self_hash_or_version_id(
                            None,
                            did,
                            query_self_hash_o,
                            query_version_id_o,
                        )
                        .await?
                        .ok_or_else(|| {
                            Error::DIDResolutionFailure2(DIDResolutionMetadata {
                                content_type: "application/did+json".to_string(),
                                error_o: Some(format!("DID resolution for {} failed", did)),
                                fetched_updates_from_vdr,
                                did_document_resolved_locally,
                                did_document_metadata_resolved_locally,
                            })
                        })?;
                    tracing::trace!(
                        ?requested_did_doc_record,
                        "requested DID document after VDR fetch"
                    );
                    let requested_did_document =
                        parse_did_document(&requested_did_doc_record.did_document_jcs)?;
                    if requested_did_document.is_deactivated() {
                        tracing::trace!(
                            ?requested_did_document,
                            "requested DID document is deactivated, thus it's the latest, and there is no next DID document"
                        );
                        // If the requested DID document is deactivated, then by construction it's the latest.
                        latest_did_doc_record_o = Some(requested_did_doc_record.clone());
                        // And we now positively know that there is no next DID document.
                        next_did_doc_record_oo = Some(None);
                    }
                    requested_did_doc_record_o = Some(requested_did_doc_record);
                } else {
                    tracing::trace!("attempting to retrieve latest DID document after VDR fetch");
                    // The latest known DID doc record is the latest, due to VDR fetch above.
                    let latest_did_doc_record = self
                        .did_doc_store
                        .get_latest_known_did_doc_record(None, did)
                        .await?
                        .ok_or_else(|| {
                            Error::DIDResolutionFailure2(DIDResolutionMetadata {
                                content_type: "application/did+json".to_string(),
                                error_o: Some(format!("DID resolution for {} failed", did)),
                                fetched_updates_from_vdr,
                                did_document_resolved_locally,
                                did_document_metadata_resolved_locally,
                            })
                        })?;
                    tracing::trace!(
                        ?latest_did_doc_record,
                        "latest DID document after VDR fetch"
                    );
                    requested_did_doc_record_o = Some(latest_did_doc_record.clone());
                    latest_did_doc_record_o = Some(latest_did_doc_record.clone());
                    next_did_doc_record_oo = Some(None);
                }
            }
            if next_did_document_o_needed && next_did_doc_record_oo.is_none() {
                assert!(requested_did_doc_record_o.is_some());
                tracing::trace!("attempting to retrieve next DID document after VDR fetch");
                let requested_did_document_version_id = u32::try_from(requested_did_doc_record_o.as_ref().unwrap().version_id).expect("version_id overflow; this is so unlikely that it's almost certainly a programmer error");
                let next_did_document_version_id = requested_did_document_version_id.checked_add(1).expect("version_id overflow; this is so unlikely that it's almost certainly a programmer error");
                tracing::trace!(
                    ?requested_did_document_version_id,
                    ?next_did_document_version_id,
                );
                let next_did_doc_record_o = self
                    .did_doc_store
                    .get_did_doc_record_with_version_id(None, did, next_did_document_version_id)
                    .await?;
                tracing::trace!(?next_did_doc_record_o, "next DID document local DB result");
                next_did_doc_record_oo = Some(next_did_doc_record_o);
            }
            if latest_did_document_needed && latest_did_doc_record_o.is_none() {
                tracing::trace!("attempting to retrieve latest DID document after VDR fetch");
                // The latest known DID doc record is the latest, due to VDR fetch above.
                let latest_did_doc_record = self
                    .did_doc_store
                    .get_latest_known_did_doc_record(None, did)
                    .await?
                    .ok_or_else(|| {
                        Error::DIDResolutionFailure2(DIDResolutionMetadata {
                            content_type: "application/did+json".to_string(),
                            error_o: Some(format!("DID resolution for {} failed", did)),
                            fetched_updates_from_vdr,
                            did_document_resolved_locally,
                            did_document_metadata_resolved_locally,
                        })
                    })?;
                tracing::trace!(
                    ?latest_did_doc_record,
                    "latest DID document local DB result"
                );
                latest_did_doc_record_o = Some(latest_did_doc_record);
            }
        } else {
            tracing::trace!("fetching updates from VDR is NOT needed to fulfill the request");
        }

        // Now assemble the requested data and metadata.
        assert!(requested_did_doc_record_o.is_some());
        let requested_did_doc_record = requested_did_doc_record_o.unwrap();
        let did_document_metadata = {
            tracing::trace!("assembling DID document metadata");

            let creation_metadata_o = if did_resolution_options.request_creation {
                assert!(root_did_doc_record_o.is_some());
                let root_did_doc_record = root_did_doc_record_o.unwrap();
                Some(CreationMetadata::new(root_did_doc_record.valid_from))
            } else {
                None
            };
            tracing::trace!(?creation_metadata_o);

            let next_update_metadata_o = if did_resolution_options.request_next {
                assert!(next_did_doc_record_oo.is_some());
                let next_did_doc_record_o = next_did_doc_record_oo.unwrap();
                if let Some(next_did_doc_record) = next_did_doc_record_o {
                    let next_version_id = u32::try_from(next_did_doc_record.version_id).expect("version_id overflow; this is so unlikely that it's almost certainly a programmer error");
                    Some(NextUpdateMetadata::new(
                        next_did_doc_record.valid_from,
                        next_version_id,
                    ))
                } else {
                    None
                }
            } else {
                None
            };
            tracing::trace!(?next_update_metadata_o);

            let latest_update_metadata_o = if did_resolution_options.request_latest {
                assert!(latest_did_doc_record_o.is_some());
                let latest_did_doc_record = latest_did_doc_record_o.as_ref().unwrap();
                Some(LatestUpdateMetadata::new(
                    latest_did_doc_record.valid_from,
                    u32::try_from(latest_did_doc_record.version_id).expect("version_id overflow; this is so unlikely that it's almost certainly a programmer error"),
                ))
            } else {
                None
            };
            tracing::trace!(?latest_update_metadata_o);

            let deactivated_o = if did_resolution_options.request_deactivated {
                assert!(latest_did_doc_record_o.is_some());
                let latest_did_doc_record = latest_did_doc_record_o.as_ref().unwrap();
                let latest_did_document =
                    parse_did_document(&latest_did_doc_record.did_document_jcs)?;
                Some(latest_did_document.is_deactivated())
            } else {
                None
            };
            tracing::trace!(?deactivated_o);

            DIDDocumentMetadata {
                creation_metadata_o,
                next_update_metadata_o,
                latest_update_metadata_o,
                deactivated_o,
            }
        };
        let did_resolution_metadata = DIDResolutionMetadata {
            content_type: "application/did+json".to_string(),
            error_o: None,
            fetched_updates_from_vdr,
            did_document_resolved_locally,
            did_document_metadata_resolved_locally,
        };
        tracing::trace!(?did_resolution_metadata);

        Ok((
            requested_did_doc_record,
            did_document_metadata,
            did_resolution_metadata,
        ))
    }
    async fn fetch_validate_and_store_did_updates_from_vdr(&self, did: &DIDStr) -> Result<()> {
        tracing::trace!("fetching DID document and requested DID document metadata from VDR");

        // Check what the latest version we do have is.
        tracing::trace!("checking latest DID document version in database");
        let latest_known_did_doc_record_o = self
            .did_doc_store
            .get_latest_known_did_doc_record(None, did)
            .await?;
        if let Some(latest_known_did_doc_record) = latest_known_did_doc_record_o.as_ref() {
            tracing::trace!(
                "latest DID document version in database: {}",
                latest_known_did_doc_record.version_id
            );
        } else {
            tracing::trace!("no DID documents in database for DID {}", did);
        }

        let latest_known_did_document_o = latest_known_did_doc_record_o
            .as_ref()
            .map(|record| parse_did_document(&record.did_document_jcs))
            .transpose()?;

        // We need to track the octet_length of did-documents.jsonl, based on what we already have.
        let mut known_did_documents_jsonl_octet_length = latest_known_did_doc_record_o
            .as_ref()
            .map(|record| record.did_documents_jsonl_octet_length)
            .unwrap_or(0) as u64;

        // Fetch the latest updates from the VDR.
        let did_documents_jsonl_update = fetch_did_documents_jsonl_update(
            &did,
            self.vdg_base_url_o.as_ref(),
            self.http_scheme_override_o.as_ref(),
            known_did_documents_jsonl_octet_length,
        )
        .await?;
        // Trim whitespace off the end (typically a newline)
        let did_documents_jsonl_update_str = did_documents_jsonl_update.trim_end();
        tracing::trace!("got did-documents.jsonl update");

        #[cfg(not(target_arch = "wasm32"))]
        let time_start = std::time::SystemTime::now();
        // TEMP HACK: Collate it all into memory
        // TODO: This needs to be bounded in memory, since the version_id comes from external
        // source and could be arbitrarily large.  Do this in bounded-size chunks.
        let mut did_document_jcs_v = Vec::new();
        let mut did_document_v = Vec::new();
        let original_prev_did_document_o = latest_known_did_document_o.clone();
        if !did_documents_jsonl_update_str.is_empty() {
            for did_document_jcs in did_documents_jsonl_update_str.split('\n') {
                tracing::trace!(?did_document_jcs, "parsing did_document_jcs");
                let did_document = parse_did_document(did_document_jcs)?;
                tracing::trace!(?did_document, "parsed did_document");
                did_document_jcs_v.push(did_document_jcs);
                did_document_v.push(did_document);
                known_did_documents_jsonl_octet_length += did_document_jcs.len() as u64 + 1;
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let duration = std::time::SystemTime::now()
                .duration_since(time_start)
                .expect("pass");
            tracing::debug!(
                "Time taken to assemble predecessor DID documents (vdg_base_url_o: {:?}): {:?}",
                self.vdg_base_url_o.as_ref().map(|url| url.as_str()),
                duration
            );
        }

        tracing::trace!("validating and storing predecessor DID documents");

        self.did_doc_store
            .validate_and_add_did_docs(
                None,
                &did_document_jcs_v,
                &did_document_v,
                original_prev_did_document_o.as_ref(),
            )
            .await?;

        Ok(())
    }
    async fn get_did_doc_record_with_self_hash_or_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        query_self_hash_o: Option<&mbx::MBHashStr>,
        query_version_id_o: Option<u32>,
    ) -> Result<Option<DIDDocRecord>> {
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
        let did_doc_record_o = match (query_self_hash_o.as_deref(), query_version_id_o) {
            (Some(self_hash_str), None) => {
                // If only a selfHash is present, then we simply use it to select the DID document.
                self.did_doc_store
                    .get_did_doc_record_with_self_hash(transaction_o, &did, self_hash_str)
                    .await?
            }
            (self_hash_str_o, Some(version_id)) => {
                // If a versionId is present, then we can use it to select the DID document.
                let did_doc_record_o = self
                    .did_doc_store
                    .get_did_doc_record_with_version_id(transaction_o, &did, version_id)
                    .await?;
                if let Some(self_hash_str) = self_hash_str_o {
                    if let Some(did_doc_record) = did_doc_record_o.as_ref() {
                        tracing::trace!(
                            "both selfHash and versionId query params present, so now a consistency check will be performed"
                        );
                        if did_doc_record.self_hash.as_str() != self_hash_str.as_str() {
                            // Note: If there is a real signature by the DID which contains the
                            // conflicting selfHash and versionId values, then that represents a fork
                            // in the DID document, which is considered illegal and fraudulent.
                            // However, simply receiving a request with conflicting selfHash and
                            // versionId values is not necessarily fraudulent, as it doesn't
                            // constitute proof that a signature was generated against a forked DID.
                            // Perhaps there could be a way to report a forked DID.
                            return Err(Error::FailedConstraint(format!(
                            "DID document with versionId {} has selfHash {} which does not match requested selfHash {}",
                            version_id,
                            did_doc_record.self_hash,
                            self_hash_str,
                        ).into()));
                        }
                    }
                }
                did_doc_record_o
            }
            (None, None) => {
                unreachable!("programmer error");
            }
        };
        if let Some(did_doc_record) = did_doc_record_o {
            // If we do have the requested DID document record,  return it.
            tracing::trace!("requested DID document already in database");
            // Do some validation on the record to make sure it's consistent with the DID doc itself.
            // This check is a bit expensive, but it's necessary to ensure the integrity of the DID doc
            // store for now -- in particular to detect attacks on the DIDDocStore.
            did_doc_record.validate_consistency()?;
            Ok(Some(did_doc_record))
        } else {
            tracing::trace!("requested DID document not in database");
            Ok(None)
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DIDResolver for DIDResolverFull {
    async fn resolve_did_document_string(
        &self,
        did_query: &str,
        did_resolution_options: DIDResolutionOptions,
    ) -> Result<(String, DIDDocumentMetadata, DIDResolutionMetadata)> {
        tracing::debug!(
            "DIDResolverFull::resolve_did_document_string; did_query: {}; did_resolution_options: {:?}",
            did_query,
            did_resolution_options
        );

        let (did_doc_record, did_document_metadata, did_resolution_metadata) = self
            .resolve_did_doc_record(did_query, did_resolution_options)
            .await?;

        tracing::trace!(
            "DIDResolverFull::resolve_did_document_string; successfully resolved DID document: {}",
            did_doc_record.did_document_jcs
        );
        Ok((
            did_doc_record.did_document_jcs,
            did_document_metadata,
            did_resolution_metadata,
        ))
    }
    fn as_verifier_resolver(&self) -> &dyn verifier_resolver::VerifierResolver {
        self
    }
    fn as_verifier_resolver_a(self: Arc<Self>) -> Arc<dyn verifier_resolver::VerifierResolver> {
        self
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl verifier_resolver::VerifierResolver for DIDResolverFull {
    async fn resolve(
        &self,
        verifier_str: &str,
    ) -> verifier_resolver::Result<Box<dyn signature_dyn::VerifierDynT>> {
        verifier_resolver_impl(verifier_str, self).await
    }
}
