//! Pure model of full-resolver locality, metadata, and resolution-metadata rules.
//!
//! This module is the single source of truth for expected
//! [`crate::ExpectedResolutionOutcome`] values in resolution-scenario vectors.
//! Its doc comments are draft normative text for the did:webplus specification.
//!
//! Authoritative implementation mirrored here:
//! `did-webplus/resolver/src/did_resolver_full.rs` ([`DIDResolverFull`] behavior).

use did_webplus_core::{
    CreationMetadata, DIDDocumentMetadata, DIDResolutionMetadata, DIDResolutionOptions,
    DIDURIComponents, LatestUpdateMetadata, NextUpdateMetadata,
};

use crate::{ExpectedResolutionOutcome, KnownDidDocumentVersion, ResolverState};

/// Result of applying the resolution-semantics oracle to one step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionStepPrediction {
    /// Expected harness-facing outcome for the step.
    pub expected: ExpectedResolutionOutcome,
    /// Resolver store state after the step (fetch stores served updates even on
    /// some post-fetch failures).
    pub resolver_state_after: ResolverState,
}

/// Pure model of [`DIDResolverFull`](https://github.com/LedgerDomain/did-webplus) locality
/// and metadata expectations.
///
/// # Normative rules (draft)
///
/// ## Needed documents
///
/// Given [`DIDResolutionOptions`]:
/// - The **requested** DID document is always needed.
/// - The **root** (version 0) is needed iff `requestCreate`.
/// - The **next** document after the requested one is needed iff `requestNext`.
/// - The **latest** document is needed iff `requestLatest` or `requestDeactivated`.
///
/// ## Local satisfiability
///
/// Resolver state is a contiguous prefix of the microledger (versions
/// `0..known_version_count`). Locality is determined **before** any VDR fetch:
///
/// - A query-param-addressed document (`versionId` and/or `selfHash`) is local
///   iff that document is present in the known prefix.
/// - A plain DID (latest) is **never** locally resolvable unless the latest-known
///   local document is deactivated (in which case it *is* the latest, there is
///   no next, and the plain-DID request resolves to that document).
/// - `next` is locally determined iff the next version is present in the known
///   prefix, **or** deactivation implies there is no next (`Some(None)`).
/// - `latest` / `deactivated` are local iff the latest-known local document is
///   deactivated.
///
/// Conflicting `versionId` and `selfHash` (both present, version found, hashes
/// disagree) is an error.
///
/// ## Local-only resolution mode
///
/// When `localResolutionOnly` is true, a conforming full resolver MUST make
/// **zero** network requests. If any needed document is not locally
/// satisfiable, resolution MUST fail while still returning
/// [`DIDResolutionMetadata`] with the three booleans set from the pre-fetch
/// determination (`fetchedUpdatesFromVDR` is false).
///
/// ## DID resolution metadata booleans
///
/// The three booleans are determined **before** any VDR fetch:
/// - `didDocumentResolvedLocally` — whether the requested document was already
///   present locally.
/// - `didDocumentMetadataResolvedLocally` — whether every *requested* metadata
///   group was locally satisfiable. When no metadata is requested, this is
///   vacuously `true`.
/// - `fetchedUpdatesFromVDR` — `true` iff a VDR fetch was performed (at most
///   one Range GET from the known octet offset per resolution).
///
/// ## Fetch efficiency
///
/// At most one VDR fetch per resolution. After a fetch, local knowledge expands
/// to the VDR's served document count for that step.
pub struct ResolutionSemantics;

impl ResolutionSemantics {
    /// Compute the expected outcome of one resolution step and the resulting
    /// resolver state.
    ///
    /// `microledger_doc_v` is the full valid microledger (contiguous
    /// `version_id == index`). `served_did_document_count` is how many leading
    /// documents the VDR serves during this step. `resolver_state` is knowledge
    /// before the step (fresh scenarios start at [`ResolverState::empty`]).
    pub fn expected_outcome(
        microledger_doc_v: &[KnownDidDocumentVersion],
        resolver_state: ResolverState,
        served_did_document_count: u32,
        did_query: &str,
        resolution_options: &DIDResolutionOptions,
    ) -> anyhow::Result<ResolutionStepPrediction> {
        Self::validate_microledger(microledger_doc_v)?;
        if served_did_document_count as usize > microledger_doc_v.len() {
            anyhow::bail!(
                "served_did_document_count ({}) exceeds microledger length ({})",
                served_did_document_count,
                microledger_doc_v.len()
            );
        }
        if resolver_state.known_version_count > served_did_document_count {
            anyhow::bail!(
                "resolver known_version_count ({}) exceeds served_did_document_count ({})",
                resolver_state.known_version_count,
                served_did_document_count
            );
        }

        let did_uri_components = DIDURIComponents::try_from(did_query)
            .map_err(|e| anyhow::anyhow!("malformed DID query: {}", e))?;
        if did_uri_components.has_fragment() {
            anyhow::bail!("DID query contains a fragment (not supported)");
        }

        let query_self_hash_o = did_uri_components.query_self_hash_o;
        let query_version_id_o = did_uri_components.query_version_id_o;
        let has_query = did_uri_components.has_query();

        let root_needed = resolution_options.request_creation;
        let next_needed = resolution_options.request_next;
        let latest_needed =
            resolution_options.request_latest || resolution_options.request_deactivated;

        let known_count = resolver_state.known_version_count;

        // --- Local phase (mirrors DIDResolverFull pre-fetch assembly) ---
        let mut root_o = if root_needed {
            Self::doc_at(microledger_doc_v, known_count, 0)
        } else {
            None
        };

        let mut requested_o: Option<&KnownDidDocumentVersion> = None;
        // None = undetermined; Some(None) = known absent; Some(Some) = known present.
        let mut next_oo: Option<Option<&KnownDidDocumentVersion>> = None;
        let mut latest_o: Option<&KnownDidDocumentVersion> = None;

        if has_query {
            match Self::lookup_with_query_params(
                microledger_doc_v,
                known_count,
                query_self_hash_o,
                query_version_id_o,
            )? {
                QueryLookup::Conflict { version_id } => {
                    return Ok(ResolutionStepPrediction {
                        expected: ExpectedResolutionOutcome::failure(
                            Self::resolution_metadata(
                                Some(format!(
                                    "conflicting versionId {} and selfHash query params",
                                    version_id
                                )),
                                false,
                                false,
                                Self::metadata_resolved_locally(
                                    root_needed,
                                    root_o.is_some(),
                                    next_needed,
                                    next_oo.is_some(),
                                    latest_needed,
                                    latest_o.is_some(),
                                ),
                            ),
                            0,
                        ),
                        resolver_state_after: resolver_state,
                    });
                }
                QueryLookup::Found(doc) => {
                    requested_o = Some(doc);
                    if doc.deactivated {
                        latest_o = Some(doc);
                        next_oo = Some(None);
                    }
                }
                QueryLookup::Missing => {}
            }
        } else if let Some(latest_known) = Self::latest_known(microledger_doc_v, known_count) {
            if latest_known.deactivated {
                latest_o = Some(latest_known);
                requested_o = Some(latest_known);
                next_oo = Some(None);
            }
        }

        if next_needed && requested_o.is_some() && next_oo.is_none() {
            let requested = requested_o.unwrap();
            let next_version_id = requested.version_id.checked_add(1).expect("version_id overflow");
            if let Some(next_doc) = Self::doc_at(microledger_doc_v, known_count, next_version_id) {
                next_oo = Some(Some(next_doc));
            }
        }

        if latest_needed && latest_o.is_none() {
            if let Some(latest_known) = Self::latest_known(microledger_doc_v, known_count) {
                if latest_known.deactivated {
                    latest_o = Some(latest_known);
                    if requested_o.is_none() {
                        requested_o = Some(latest_known);
                    }
                    if next_oo.is_none() {
                        next_oo = Some(None);
                    }
                }
            }
        }

        if root_needed && root_o.is_none() {
            root_o = Self::doc_at(microledger_doc_v, known_count, 0);
        }

        let did_document_resolved_locally = requested_o.is_some();
        let did_document_metadata_resolved_locally = Self::metadata_resolved_locally(
            root_needed,
            root_o.is_some(),
            next_needed,
            next_oo.is_some(),
            latest_needed,
            latest_o.is_some(),
        );

        let fetch_needed = (root_needed && root_o.is_none())
            || requested_o.is_none()
            || (next_needed && next_oo.is_none())
            || (latest_needed && latest_o.is_none());

        if fetch_needed && resolution_options.local_resolution_only {
            return Ok(ResolutionStepPrediction {
                expected: ExpectedResolutionOutcome::failure(
                    Self::resolution_metadata(
                        Some(format!(
                            "local-only DID resolution for {} was not able to complete",
                            did_query
                        )),
                        false,
                        did_document_resolved_locally,
                        did_document_metadata_resolved_locally,
                    ),
                    0,
                ),
                resolver_state_after: resolver_state,
            });
        }

        let mut fetched_updates_from_vdr = false;
        let mut resolver_state_after = resolver_state;
        let vdr_request_count;

        if fetch_needed {
            // At most one Range GET; store expands to what the VDR serves.
            fetched_updates_from_vdr = true;
            vdr_request_count = 1;
            resolver_state_after = ResolverState {
                known_version_count: served_did_document_count,
            };
            let known_after = served_did_document_count;

            if root_needed && root_o.is_none() {
                root_o = Self::doc_at(microledger_doc_v, known_after, 0);
                if root_o.is_none() {
                    return Ok(ResolutionStepPrediction {
                        expected: ExpectedResolutionOutcome::failure(
                            Self::resolution_metadata(
                                Some(format!(
                                    "DID resolution for {} failed (root DID document resolution failed)",
                                    did_query
                                )),
                                fetched_updates_from_vdr,
                                did_document_resolved_locally,
                                did_document_metadata_resolved_locally,
                            ),
                            vdr_request_count,
                        ),
                        resolver_state_after,
                    });
                }
            }

            if requested_o.is_none() {
                if has_query {
                    match Self::lookup_with_query_params(
                        microledger_doc_v,
                        known_after,
                        query_self_hash_o,
                        query_version_id_o,
                    )? {
                        QueryLookup::Conflict { version_id } => {
                            return Ok(ResolutionStepPrediction {
                                expected: ExpectedResolutionOutcome::failure(
                                    Self::resolution_metadata(
                                        Some(format!(
                                            "conflicting versionId {} and selfHash query params",
                                            version_id
                                        )),
                                        fetched_updates_from_vdr,
                                        did_document_resolved_locally,
                                        did_document_metadata_resolved_locally,
                                    ),
                                    vdr_request_count,
                                ),
                                resolver_state_after,
                            });
                        }
                        QueryLookup::Found(doc) => {
                            if doc.deactivated {
                                latest_o = Some(doc);
                                next_oo = Some(None);
                            }
                            requested_o = Some(doc);
                        }
                        QueryLookup::Missing => {
                            return Ok(ResolutionStepPrediction {
                                expected: ExpectedResolutionOutcome::failure(
                                    Self::resolution_metadata(
                                        Some(format!("DID resolution for {} failed", did_query)),
                                        fetched_updates_from_vdr,
                                        did_document_resolved_locally,
                                        did_document_metadata_resolved_locally,
                                    ),
                                    vdr_request_count,
                                ),
                                resolver_state_after,
                            });
                        }
                    }
                } else if let Some(latest_doc) =
                    Self::latest_known(microledger_doc_v, known_after)
                {
                    requested_o = Some(latest_doc);
                    latest_o = Some(latest_doc);
                    next_oo = Some(None);
                } else {
                    return Ok(ResolutionStepPrediction {
                        expected: ExpectedResolutionOutcome::failure(
                            Self::resolution_metadata(
                                Some(format!("DID resolution for {} failed", did_query)),
                                fetched_updates_from_vdr,
                                did_document_resolved_locally,
                                did_document_metadata_resolved_locally,
                            ),
                            vdr_request_count,
                        ),
                        resolver_state_after,
                    });
                }
            }

            if next_needed && next_oo.is_none() {
                let requested = requested_o.expect("requested must be present before next lookup");
                let next_version_id =
                    requested.version_id.checked_add(1).expect("version_id overflow");
                next_oo = Some(Self::doc_at(
                    microledger_doc_v,
                    known_after,
                    next_version_id,
                ));
            }

            if latest_needed && latest_o.is_none() {
                match Self::latest_known(microledger_doc_v, known_after) {
                    Some(latest_doc) => latest_o = Some(latest_doc),
                    None => {
                        return Ok(ResolutionStepPrediction {
                            expected: ExpectedResolutionOutcome::failure(
                                Self::resolution_metadata(
                                    Some(format!("DID resolution for {} failed", did_query)),
                                    fetched_updates_from_vdr,
                                    did_document_resolved_locally,
                                    did_document_metadata_resolved_locally,
                                ),
                                vdr_request_count,
                            ),
                            resolver_state_after,
                        });
                    }
                }
            }
        } else {
            vdr_request_count = 0;
        }

        let requested = requested_o.expect("successful path requires requested document");
        let did_document_metadata = Self::assemble_metadata(
            resolution_options,
            root_o,
            next_oo,
            latest_o,
        );

        Ok(ResolutionStepPrediction {
            expected: ExpectedResolutionOutcome::success(
                requested.version_id,
                requested.self_hash.clone(),
                did_document_metadata,
                Self::resolution_metadata(
                    None,
                    fetched_updates_from_vdr,
                    did_document_resolved_locally,
                    did_document_metadata_resolved_locally,
                ),
                vdr_request_count,
            ),
            resolver_state_after,
        })
    }

    fn validate_microledger(microledger_doc_v: &[KnownDidDocumentVersion]) -> anyhow::Result<()> {
        for (i, doc) in microledger_doc_v.iter().enumerate() {
            if doc.version_id as usize != i {
                anyhow::bail!(
                    "microledger version_id mismatch at index {}: got {}",
                    i,
                    doc.version_id
                );
            }
        }
        if let Some(deactivated_i) = microledger_doc_v.iter().position(|d| d.deactivated) {
            if deactivated_i + 1 != microledger_doc_v.len() {
                anyhow::bail!("deactivated document must be the last in the microledger");
            }
        }
        Ok(())
    }

    fn doc_at(
        microledger_doc_v: &[KnownDidDocumentVersion],
        known_count: u32,
        version_id: u32,
    ) -> Option<&KnownDidDocumentVersion> {
        if version_id < known_count {
            microledger_doc_v.get(version_id as usize)
        } else {
            None
        }
    }

    fn latest_known(
        microledger_doc_v: &[KnownDidDocumentVersion],
        known_count: u32,
    ) -> Option<&KnownDidDocumentVersion> {
        if known_count == 0 {
            None
        } else {
            Self::doc_at(microledger_doc_v, known_count, known_count - 1)
        }
    }

    fn lookup_with_query_params<'a>(
        microledger_doc_v: &'a [KnownDidDocumentVersion],
        known_count: u32,
        query_self_hash_o: Option<&mbx::MBHashStr>,
        query_version_id_o: Option<u32>,
    ) -> anyhow::Result<QueryLookup<'a>> {
        match (query_self_hash_o, query_version_id_o) {
            (Some(self_hash), None) => {
                let found = (0..known_count).find_map(|version_id| {
                    let doc = Self::doc_at(microledger_doc_v, known_count, version_id)?;
                    if doc.self_hash.as_str() == self_hash.as_str() {
                        Some(doc)
                    } else {
                        None
                    }
                });
                Ok(found.map(QueryLookup::Found).unwrap_or(QueryLookup::Missing))
            }
            (self_hash_o, Some(version_id)) => {
                let doc_o = Self::doc_at(microledger_doc_v, known_count, version_id);
                if let (Some(self_hash), Some(doc)) = (self_hash_o, doc_o) {
                    if doc.self_hash.as_str() != self_hash.as_str() {
                        return Ok(QueryLookup::Conflict { version_id });
                    }
                }
                Ok(doc_o
                    .map(QueryLookup::Found)
                    .unwrap_or(QueryLookup::Missing))
            }
            (None, None) => anyhow::bail!(
                "programmer error: lookup_with_query_params called without query params"
            ),
        }
    }

    fn metadata_resolved_locally(
        root_needed: bool,
        root_present: bool,
        next_needed: bool,
        next_determined: bool,
        latest_needed: bool,
        latest_present: bool,
    ) -> bool {
        (!root_needed || root_present)
            && (!next_needed || next_determined)
            && (!latest_needed || latest_present)
    }

    fn resolution_metadata(
        error_o: Option<String>,
        fetched_updates_from_vdr: bool,
        did_document_resolved_locally: bool,
        did_document_metadata_resolved_locally: bool,
    ) -> DIDResolutionMetadata {
        DIDResolutionMetadata {
            content_type: "application/did+json".to_string(),
            error_o,
            fetched_updates_from_vdr,
            did_document_resolved_locally,
            did_document_metadata_resolved_locally,
        }
    }

    fn assemble_metadata(
        resolution_options: &DIDResolutionOptions,
        root_o: Option<&KnownDidDocumentVersion>,
        next_oo: Option<Option<&KnownDidDocumentVersion>>,
        latest_o: Option<&KnownDidDocumentVersion>,
    ) -> DIDDocumentMetadata {
        let creation_metadata_o = if resolution_options.request_creation {
            let root = root_o.expect("creation metadata requires root");
            Some(CreationMetadata::new(root.valid_from))
        } else {
            None
        };

        let next_update_metadata_o = if resolution_options.request_next {
            let next_o = next_oo.expect("next metadata requires next determination");
            next_o.map(|next_doc| NextUpdateMetadata::new(next_doc.valid_from, next_doc.version_id))
        } else {
            None
        };

        let latest_update_metadata_o = if resolution_options.request_latest {
            let latest = latest_o.expect("latest metadata requires latest");
            Some(LatestUpdateMetadata::new(
                latest.valid_from,
                latest.version_id,
            ))
        } else {
            None
        };

        let deactivated_o = if resolution_options.request_deactivated {
            let latest = latest_o.expect("deactivated metadata requires latest");
            Some(latest.deactivated)
        } else {
            None
        };

        DIDDocumentMetadata {
            creation_metadata_o,
            next_update_metadata_o,
            latest_update_metadata_o,
            deactivated_o,
        }
    }
}

enum QueryLookup<'a> {
    Found(&'a KnownDidDocumentVersion),
    Missing,
    Conflict { version_id: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeterministicRng, KnownDidDocumentVersion, ResolverState};
    use did_webplus_core::{DIDResolutionOptions, truncated_to_seconds};
    use time::macros::datetime;

    fn hash(n: u8) -> mbx::MBHash {
        // Distinct, valid-looking multibase hashes (only uniqueness matters for the oracle).
        let s = match n {
            1 => "uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ",
            2 => "uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg",
            3 => "uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw",
            4 => "uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA",
            9 => "uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQ",
            _ => panic!("unsupported fixture hash index"),
        };
        mbx::MBHash::try_from(s).expect("fixture hash")
    }

    fn doc(version_id: u32, hash_n: u8, deactivated: bool) -> KnownDidDocumentVersion {
        // Non-zero fractional milliseconds so metadata truncation
        // (`*Milliseconds` -> whole-seconds fields) is exercised.
        let millisecond =
            DeterministicRng::fractional_millisecond_for_index(version_id);
        KnownDidDocumentVersion {
            version_id,
            self_hash: hash(hash_n),
            valid_from: datetime!(2025-01-01 00:00:00 UTC)
                + time::Duration::seconds(version_id as i64)
                + time::Duration::milliseconds(millisecond as i64),
            deactivated,
        }
    }

    fn ledger_active() -> Vec<KnownDidDocumentVersion> {
        vec![doc(0, 1, false), doc(1, 2, false), doc(2, 3, false), doc(3, 4, false)]
    }

    fn ledger_deactivated() -> Vec<KnownDidDocumentVersion> {
        vec![
            doc(0, 1, false),
            doc(1, 2, false),
            doc(2, 3, false),
            doc(3, 4, true),
        ]
    }

    const DID: &str = "did:webplus:example.com:uEiAWCleApqPkQg-DKbql-C5OOyZ7ydUgq7G_rHepYEukHg";

    fn predict(
        ledger: &[KnownDidDocumentVersion],
        known: u32,
        served: u32,
        query: &str,
        options: DIDResolutionOptions,
    ) -> ResolutionStepPrediction {
        ResolutionSemantics::expected_outcome(
            ledger,
            ResolverState {
                known_version_count: known,
            },
            served,
            query,
            &options,
        )
        .expect("oracle")
    }

    #[test]
    fn cold_plain_did_no_metadata_fetches() {
        let ledger = ledger_active();
        let prediction = predict(
            &ledger,
            0,
            4,
            DID,
            DIDResolutionOptions::no_metadata(false),
        );
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.did_document_version_id_o, Some(3));
        assert_eq!(expected.vdr_request_count, 1);
        assert!(expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(!expected.did_resolution_metadata.did_document_resolved_locally);
        // Vacuous: no metadata requested.
        assert!(
            expected
                .did_resolution_metadata
                .did_document_metadata_resolved_locally
        );
        assert_eq!(prediction.resolver_state_after.known_version_count, 4);
        let meta = expected.did_document_metadata_o.as_ref().unwrap();
        assert!(meta.creation_metadata_o.is_none());
        assert!(meta.next_update_metadata_o.is_none());
        assert!(meta.latest_update_metadata_o.is_none());
        assert!(meta.deactivated_o.is_none());
    }

    #[test]
    fn warm_version_id_resolves_locally() {
        let ledger = ledger_active();
        let query = format!("{}?versionId=1", DID);
        let prediction = predict(
            &ledger,
            4,
            4,
            &query,
            DIDResolutionOptions::no_metadata(false),
        );
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.did_document_version_id_o, Some(1));
        assert_eq!(expected.vdr_request_count, 0);
        assert!(!expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(
            expected
                .did_resolution_metadata
                .did_document_metadata_resolved_locally
        );
        assert_eq!(prediction.resolver_state_after.known_version_count, 4);
    }

    #[test]
    fn warm_self_hash_resolves_locally() {
        let ledger = ledger_active();
        let query = format!("{}?selfHash={}", DID, ledger[2].self_hash);
        let prediction = predict(
            &ledger,
            4,
            4,
            &query,
            DIDResolutionOptions::no_metadata(false),
        );
        assert!(prediction.expected.success);
        assert_eq!(prediction.expected.did_document_version_id_o, Some(2));
        assert_eq!(prediction.expected.vdr_request_count, 0);
        assert!(
            prediction
                .expected
                .did_resolution_metadata
                .did_document_resolved_locally
        );
    }

    #[test]
    fn warm_both_params_agree_resolves_locally() {
        let ledger = ledger_active();
        let query = format!(
            "{}?selfHash={}&versionId=1",
            DID, ledger[1].self_hash
        );
        let prediction = predict(
            &ledger,
            4,
            4,
            &query,
            DIDResolutionOptions::no_metadata(false),
        );
        assert!(prediction.expected.success);
        assert_eq!(prediction.expected.did_document_version_id_o, Some(1));
        assert_eq!(prediction.expected.vdr_request_count, 0);
    }

    #[test]
    fn conflicting_query_params_errors_without_fetch_when_local() {
        let ledger = ledger_active();
        let query = format!(
            "{}?selfHash={}&versionId=1",
            DID, ledger[2].self_hash
        );
        let prediction = predict(
            &ledger,
            4,
            4,
            &query,
            DIDResolutionOptions::no_metadata(false),
        );
        assert!(!prediction.expected.success);
        assert_eq!(prediction.expected.vdr_request_count, 0);
        assert!(!prediction.expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(prediction.expected.did_resolution_metadata.error_o.is_some());
        assert_eq!(prediction.resolver_state_after.known_version_count, 4);
    }

    #[test]
    fn plain_did_always_fetches_when_not_deactivated() {
        let ledger = ledger_active();
        let prediction = predict(
            &ledger,
            4,
            4,
            DID,
            DIDResolutionOptions::no_metadata(false),
        );
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.did_document_version_id_o, Some(3));
        assert_eq!(expected.vdr_request_count, 1);
        assert!(expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(!expected.did_resolution_metadata.did_document_resolved_locally);
    }

    #[test]
    fn request_creation_cold_fetches_and_populates_metadata() {
        let ledger = ledger_active();
        let mut options = DIDResolutionOptions::no_metadata(false);
        options.request_creation = true;
        let prediction = predict(&ledger, 0, 4, DID, options);
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.vdr_request_count, 1);
        assert!(!expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(!expected.did_resolution_metadata.did_document_metadata_resolved_locally);
        let meta = expected.did_document_metadata_o.as_ref().unwrap();
        let creation = meta.creation_metadata_o.as_ref().unwrap();
        assert_eq!(
            creation.creation_time_milliseconds(),
            ledger[0].valid_from
        );
        assert_eq!(
            creation.creation_time(),
            truncated_to_seconds(ledger[0].valid_from)
        );
        assert_ne!(
            creation.creation_time(),
            creation.creation_time_milliseconds(),
            "fractional validFrom must make created != createdMilliseconds"
        );
    }

    #[test]
    fn request_creation_warm_version_is_local() {
        let ledger = ledger_active();
        let mut options = DIDResolutionOptions::no_metadata(false);
        options.request_creation = true;
        let query = format!("{}?versionId=2", DID);
        let prediction = predict(&ledger, 4, 4, &query, options);
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.vdr_request_count, 0);
        assert!(expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(
            expected
                .did_resolution_metadata
                .did_document_metadata_resolved_locally
        );
    }

    #[test]
    fn request_next_with_local_next_no_fetch() {
        let ledger = ledger_active();
        let mut options = DIDResolutionOptions::no_metadata(false);
        options.request_next = true;
        let query = format!("{}?versionId=1", DID);
        let prediction = predict(&ledger, 4, 4, &query, options);
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.vdr_request_count, 0);
        let meta = expected.did_document_metadata_o.as_ref().unwrap();
        let next = meta.next_update_metadata_o.as_ref().unwrap();
        assert_eq!(next.next_version_id(), "2");
        assert_eq!(next.next_update_time_milliseconds(), ledger[2].valid_from);
        assert_eq!(
            next.next_update_time(),
            truncated_to_seconds(ledger[2].valid_from)
        );
        assert_ne!(
            next.next_update_time(),
            next.next_update_time_milliseconds()
        );
    }

    #[test]
    fn request_next_at_latest_requires_fetch_to_confirm_absence() {
        let ledger = ledger_active();
        let mut options = DIDResolutionOptions::no_metadata(false);
        options.request_next = true;
        let query = format!("{}?versionId=3", DID);
        let prediction = predict(&ledger, 4, 4, &query, options);
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.vdr_request_count, 1);
        assert!(expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(!expected.did_resolution_metadata.did_document_metadata_resolved_locally);
        let meta = expected.did_document_metadata_o.as_ref().unwrap();
        assert!(meta.next_update_metadata_o.is_none());
    }

    #[test]
    fn request_latest_forces_fetch_when_not_deactivated() {
        let ledger = ledger_active();
        let mut options = DIDResolutionOptions::no_metadata(false);
        options.request_latest = true;
        let query = format!("{}?versionId=1", DID);
        let prediction = predict(&ledger, 4, 4, &query, options);
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.vdr_request_count, 1);
        assert!(expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(!expected.did_resolution_metadata.did_document_metadata_resolved_locally);
        let meta = expected.did_document_metadata_o.as_ref().unwrap();
        let latest = meta.latest_update_metadata_o.as_ref().unwrap();
        assert_eq!(latest.latest_version_id(), "3");
        assert_eq!(
            latest.latest_update_time_milliseconds(),
            ledger[3].valid_from
        );
        assert_eq!(
            latest.latest_update_time(),
            truncated_to_seconds(ledger[3].valid_from)
        );
        assert_ne!(
            latest.latest_update_time(),
            latest.latest_update_time_milliseconds()
        );
    }

    #[test]
    fn request_deactivated_forces_fetch_when_not_deactivated() {
        let ledger = ledger_active();
        let mut options = DIDResolutionOptions::no_metadata(false);
        options.request_deactivated = true;
        let query = format!("{}?versionId=0", DID);
        let prediction = predict(&ledger, 4, 4, &query, options);
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.vdr_request_count, 1);
        assert_eq!(
            expected
                .did_document_metadata_o
                .as_ref()
                .unwrap()
                .deactivated_o,
            Some(false)
        );
    }

    #[test]
    fn deactivated_all_local_allows_local_only_plain_did() {
        let ledger = ledger_deactivated();
        let prediction = predict(
            &ledger,
            4,
            4,
            DID,
            DIDResolutionOptions::all_metadata(true),
        );
        let expected = &prediction.expected;
        assert!(expected.success);
        assert_eq!(expected.vdr_request_count, 0);
        assert!(!expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(
            expected
                .did_resolution_metadata
                .did_document_metadata_resolved_locally
        );
        assert_eq!(expected.did_document_version_id_o, Some(3));
        let meta = expected.did_document_metadata_o.as_ref().unwrap();
        assert!(meta.next_update_metadata_o.is_none());
        assert_eq!(meta.deactivated_o, Some(true));
    }

    #[test]
    fn local_only_cold_errors() {
        let ledger = ledger_active();
        let prediction = predict(
            &ledger,
            0,
            4,
            DID,
            DIDResolutionOptions::no_metadata(true),
        );
        let expected = &prediction.expected;
        assert!(!expected.success);
        assert_eq!(expected.vdr_request_count, 0);
        assert!(!expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(!expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(
            expected
                .did_resolution_metadata
                .did_document_metadata_resolved_locally
        );
        assert_eq!(prediction.resolver_state_after.known_version_count, 0);
    }

    #[test]
    fn local_only_warm_version_succeeds() {
        let ledger = ledger_active();
        let query = format!("{}?versionId=2", DID);
        let prediction = predict(
            &ledger,
            4,
            4,
            &query,
            DIDResolutionOptions::no_metadata(true),
        );
        assert!(prediction.expected.success);
        assert_eq!(prediction.expected.vdr_request_count, 0);
    }

    #[test]
    fn local_only_warm_plain_did_errors() {
        let ledger = ledger_active();
        let prediction = predict(
            &ledger,
            4,
            4,
            DID,
            DIDResolutionOptions::no_metadata(true),
        );
        let expected = &prediction.expected;
        assert!(!expected.success);
        assert_eq!(expected.vdr_request_count, 0);
        assert!(!expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(expected.did_resolution_metadata.error_o.is_some());
    }

    #[test]
    fn local_only_warm_request_latest_errors() {
        let ledger = ledger_active();
        let mut options = DIDResolutionOptions::no_metadata(true);
        options.request_latest = true;
        let query = format!("{}?versionId=1", DID);
        let prediction = predict(&ledger, 4, 4, &query, options);
        let expected = &prediction.expected;
        assert!(!expected.success);
        assert_eq!(expected.vdr_request_count, 0);
        assert!(expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(!expected.did_resolution_metadata.did_document_metadata_resolved_locally);
    }

    #[test]
    fn incremental_range_fetch_expands_state() {
        let ledger = ledger_active();
        let step1 = predict(
            &ledger,
            0,
            1,
            DID,
            DIDResolutionOptions::no_metadata(false),
        );
        assert!(step1.expected.success);
        assert_eq!(step1.expected.did_document_version_id_o, Some(0));
        assert_eq!(step1.expected.vdr_request_count, 1);
        assert_eq!(step1.resolver_state_after.known_version_count, 1);

        let step2 = predict(
            &ledger,
            step1.resolver_state_after.known_version_count,
            4,
            DID,
            DIDResolutionOptions::no_metadata(false),
        );
        assert!(step2.expected.success);
        assert_eq!(step2.expected.did_document_version_id_o, Some(3));
        assert_eq!(step2.expected.vdr_request_count, 1);
        assert_eq!(step2.resolver_state_after.known_version_count, 4);
    }

    #[test]
    fn version_beyond_served_fetches_then_errors() {
        let ledger = ledger_active();
        let query = format!("{}?versionId=3", DID);
        let prediction = predict(
            &ledger,
            0,
            2,
            &query,
            DIDResolutionOptions::no_metadata(false),
        );
        let expected = &prediction.expected;
        assert!(!expected.success);
        assert_eq!(expected.vdr_request_count, 1);
        assert!(expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(!expected.did_resolution_metadata.did_document_resolved_locally);
        // Fetch still stores what was served.
        assert_eq!(prediction.resolver_state_after.known_version_count, 2);
    }
}
