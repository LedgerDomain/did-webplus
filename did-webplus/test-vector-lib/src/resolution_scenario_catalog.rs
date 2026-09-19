//! Resolution-scenario catalog: stateful vectors for locality, metadata, and local-only mode.
//!
//! Each vector owns a fully valid microledger (~4 versions; one deactivated variant) plus a
//! [`ResolutionScenario`] whose step expectations are filled by
//! [`crate::ResolutionSemantics`].
//!
//! Microledgers are built with [`DeterministicRng::with_fractional_timestamps`] so
//! `validFrom` values carry deterministic non-zero millisecond components and
//! expected DID document metadata exercises floor-to-seconds truncation from
//! `*Milliseconds` fields to their DID-spec counterparts.

use did_webplus_core::DIDResolutionOptions;
use did_webplus_mock::MicroledgerView;

use crate::{
    DeterministicRng, Expected, KnownDidDocumentVersion, MicroledgerBuilder,
    RESOLUTION_SCENARIO_CATEGORY, ResolutionScenario, ResolutionSemantics, ResolutionStep,
    ResolverState, TestVector, TestVectorParams,
};

const CATEGORY: &str = RESOLUTION_SCENARIO_CATEGORY;
const SPEC_REF: &str = "#did-resolution-metadata";

/// Active microledger length used by most scenarios (versions `0..3`).
const ACTIVE_UPDATE_COUNT: u32 = 3;
/// Active updates before a final deactivation tombstone (versions `0..2` active, `3` deactivated).
const DEACTIVATED_UPDATE_COUNT_BEFORE_TOMBSTONE: u32 = 2;

/// A named deterministic resolution-scenario factory.
#[derive(Clone, Copy)]
pub struct ResolutionScenarioDefinition {
    /// Stable vector / scenario name used for catalog lookup and RNG derivation.
    pub name: &'static str,
    /// Human-readable summary of what the scenario exercises.
    pub description: &'static str,
    /// Factory which generates the microledger vector and filled-in scenario.
    pub factory: fn(
        TestVectorParams,
        DeterministicRng,
    ) -> anyhow::Result<(TestVector, ResolutionScenario)>,
}

impl std::fmt::Debug for ResolutionScenarioDefinition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolutionScenarioDefinition")
            .field("name", &self.name)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

/// One step before the oracle fills in [`ResolutionStep::expected`].
struct StepInput {
    served_did_document_count: u32,
    did_query: String,
    resolution_options: DIDResolutionOptions,
}

fn known_version_v(
    builder: &MicroledgerBuilder,
) -> anyhow::Result<Vec<KnownDidDocumentVersion>> {
    let (_, iter) = builder.microledger().view().select_did_documents(None, None);
    iter.map(KnownDidDocumentVersion::from_did_document)
        .collect()
}

fn build_active_ledger(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(MicroledgerBuilder, Vec<KnownDidDocumentVersion>)> {
    // Fractional `validFrom` so expected metadata exercises floor-to-seconds
    // truncation from `*Milliseconds` fields to their DID-spec counterparts.
    let builder = MicroledgerBuilder::create_with_updates(
        params,
        rng.with_fractional_timestamps(),
        ACTIVE_UPDATE_COUNT,
    )?;
    let known_version_v = known_version_v(&builder)?;
    Ok((builder, known_version_v))
}

fn build_deactivated_ledger(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(MicroledgerBuilder, Vec<KnownDidDocumentVersion>)> {
    let mut builder = MicroledgerBuilder::create_with_updates(
        params,
        rng.with_fractional_timestamps(),
        DEACTIVATED_UPDATE_COUNT_BEFORE_TOMBSTONE,
    )?;
    builder.deactivate()?;
    let known_version_v = known_version_v(&builder)?;
    Ok((builder, known_version_v))
}

fn fill_steps(
    microledger_doc_v: &[KnownDidDocumentVersion],
    step_input_v: Vec<StepInput>,
) -> anyhow::Result<Vec<ResolutionStep>> {
    let mut resolver_state = ResolverState::empty();
    let mut step_v = Vec::with_capacity(step_input_v.len());
    let mut prev_served_o = None::<u32>;
    for step_input in step_input_v {
        if let Some(prev_served) = prev_served_o {
            anyhow::ensure!(
                step_input.served_did_document_count >= prev_served,
                "served_did_document_count must be monotonically non-decreasing"
            );
        }
        prev_served_o = Some(step_input.served_did_document_count);

        let prediction = ResolutionSemantics::expected_outcome(
            microledger_doc_v,
            resolver_state,
            step_input.served_did_document_count,
            &step_input.did_query,
            &step_input.resolution_options,
        )?;
        step_v.push(ResolutionStep {
            served_did_document_count: step_input.served_did_document_count,
            did_query: step_input.did_query,
            resolution_options: step_input.resolution_options,
            expected: prediction.expected,
        });
        resolver_state = prediction.resolver_state_after;
    }
    Ok(step_v)
}

fn finish(
    name: &str,
    description: &str,
    builder: MicroledgerBuilder,
    known_version_v: &[KnownDidDocumentVersion],
    step_input_v: Vec<StepInput>,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let params = builder.params().clone();
    let did = builder.did().clone();
    let jsonl_line_v = builder.canonical_jsonl_lines()?;
    let step_v = fill_steps(known_version_v, step_input_v)?;
    let scenario = ResolutionScenario::new(
        name,
        description,
        vec![SPEC_REF.to_owned()],
        did.clone(),
        step_v,
    );
    let test_vector = TestVector {
        name: name.to_owned(),
        category: CATEGORY.to_owned(),
        description: description.to_owned(),
        spec_ref_v: vec![SPEC_REF.to_owned()],
        expected: Expected::fully_valid(jsonl_line_v.len() as u32),
        jsonl_line_v,
        did,
        params,
    };
    Ok((test_vector, scenario))
}

fn all_count(known_version_v: &[KnownDidDocumentVersion]) -> u32 {
    known_version_v.len() as u32
}

fn warm_plain_step(did: &did_webplus_core::DID, served: u32) -> StepInput {
    StepInput {
        served_did_document_count: served,
        did_query: did.to_string(),
        resolution_options: DIDResolutionOptions::no_metadata(false),
    }
}

fn cold_plain_did_no_metadata(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    finish(
        "cold-plain-did-no-metadata",
        "Cold plain-DID resolve with no metadata: one VDR fetch; document not local; metadata vacuous.",
        builder,
        &known_version_v,
        vec![StepInput {
            served_did_document_count: served,
            did_query: did.to_string(),
            resolution_options: DIDResolutionOptions::no_metadata(false),
        }],
    )
}

fn warm_version_id(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let query = did.with_query_version_id(1).to_string();
    finish(
        "warm-version-id",
        "After a cold fetch, versionId query resolves locally with zero VDR requests.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: DIDResolutionOptions::no_metadata(false),
            },
        ],
    )
}

fn warm_self_hash(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let query = did
        .with_query_self_hash(&known_version_v[2].self_hash)
        .to_string();
    finish(
        "warm-self-hash",
        "After a cold fetch, selfHash query resolves locally with zero VDR requests.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: DIDResolutionOptions::no_metadata(false),
            },
        ],
    )
}

fn warm_both_params(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let query = did
        .with_queries(&known_version_v[1].self_hash, 1)
        .to_string();
    finish(
        "warm-both-params",
        "After a cold fetch, agreeing selfHash and versionId query params resolve locally.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: DIDResolutionOptions::no_metadata(false),
            },
        ],
    )
}

fn conflicting_query_params(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    // selfHash of version 2 with versionId 1 — disagree when version 1 is local.
    let query = format!(
        "{}?selfHash={}&versionId=1",
        did, known_version_v[2].self_hash
    );
    finish(
        "conflicting-query-params",
        "Disagreeing versionId and selfHash query params error without a VDR fetch when local.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: DIDResolutionOptions::no_metadata(false),
            },
        ],
    )
}

fn plain_did_always_fetches(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    finish(
        "plain-did-always-fetches",
        "Warm plain-DID resolve still fetches from the VDR when the latest-known doc is not deactivated.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: did.to_string(),
                resolution_options: DIDResolutionOptions::no_metadata(false),
            },
        ],
    )
}

fn request_creation_cold(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let mut options = DIDResolutionOptions::no_metadata(false);
    options.request_creation = true;
    finish(
        "request-creation-cold",
        "Cold plain-DID resolve with requestCreate fetches and populates creation metadata.",
        builder,
        &known_version_v,
        vec![StepInput {
            served_did_document_count: served,
            did_query: did.to_string(),
            resolution_options: options,
        }],
    )
}

fn request_creation_warm(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let mut options = DIDResolutionOptions::no_metadata(false);
    options.request_creation = true;
    let query = did.with_query_version_id(2).to_string();
    finish(
        "request-creation-warm",
        "Warm versionId resolve with requestCreate is fully local (root already known).",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: options,
            },
        ],
    )
}

fn request_next_with_local_next(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let mut options = DIDResolutionOptions::no_metadata(false);
    options.request_next = true;
    let query = did.with_query_version_id(1).to_string();
    finish(
        "request-next-with-local-next",
        "Warm versionId resolve with requestNext when the next version is already local.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: options,
            },
        ],
    )
}

fn request_next_at_latest(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let mut options = DIDResolutionOptions::no_metadata(false);
    options.request_next = true;
    let latest_version_id = served - 1;
    let query = did.with_query_version_id(latest_version_id).to_string();
    finish(
        "request-next-at-latest",
        "Warm resolve of the latest version with requestNext requires a fetch to confirm next is absent.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: options,
            },
        ],
    )
}

fn request_latest_forces_fetch(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let mut options = DIDResolutionOptions::no_metadata(false);
    options.request_latest = true;
    let query = did.with_query_version_id(1).to_string();
    finish(
        "request-latest-forces-fetch",
        "Warm versionId resolve with requestLatest forces a VDR fetch when not deactivated.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: options,
            },
        ],
    )
}

fn request_deactivated_forces_fetch(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let mut options = DIDResolutionOptions::no_metadata(false);
    options.request_deactivated = true;
    let query = did.with_query_version_id(0).to_string();
    finish(
        "request-deactivated-forces-fetch",
        "Warm versionId resolve with requestDeactivated forces a VDR fetch when not deactivated.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: query,
                resolution_options: options,
            },
        ],
    )
}

fn deactivated_all_local(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_deactivated_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    finish(
        "deactivated-all-local",
        "After the deactivation tombstone is known, all metadata and plain-DID resolution succeed local-only.",
        builder,
        &known_version_v,
        vec![
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: did.to_string(),
                resolution_options: DIDResolutionOptions::all_metadata(true),
            },
        ],
    )
}

fn local_only_matrix(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served = all_count(&known_version_v);
    let did = builder.did().clone();
    let version_query = did.with_query_version_id(2).to_string();
    let mut request_latest = DIDResolutionOptions::no_metadata(true);
    request_latest.request_latest = true;
    finish(
        "local-only-matrix",
        "Local-only mode matrix: cold error; warm version-query success; warm plain-DID error; warm requestLatest error.",
        builder,
        &known_version_v,
        vec![
            StepInput {
                served_did_document_count: served,
                did_query: did.to_string(),
                resolution_options: DIDResolutionOptions::no_metadata(true),
            },
            // Prime the store for subsequent warm local-only steps.
            warm_plain_step(&did, served),
            StepInput {
                served_did_document_count: served,
                did_query: version_query,
                resolution_options: DIDResolutionOptions::no_metadata(true),
            },
            StepInput {
                served_did_document_count: served,
                did_query: did.to_string(),
                resolution_options: DIDResolutionOptions::no_metadata(true),
            },
            StepInput {
                served_did_document_count: served,
                did_query: did.with_query_version_id(1).to_string(),
                resolution_options: request_latest,
            },
        ],
    )
}

fn incremental_range_fetch(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let served_all = all_count(&known_version_v);
    let did = builder.did().clone();
    finish(
        "incremental-range-fetch",
        "Step 1 serves one document; step 2 serves all and resolves latest via a single Range continuation.",
        builder,
        &known_version_v,
        vec![
            StepInput {
                served_did_document_count: 1,
                did_query: did.to_string(),
                resolution_options: DIDResolutionOptions::no_metadata(false),
            },
            StepInput {
                served_did_document_count: served_all,
                did_query: did.to_string(),
                resolution_options: DIDResolutionOptions::no_metadata(false),
            },
        ],
    )
}

fn version_beyond_served(
    params: TestVectorParams,
    rng: DeterministicRng,
) -> anyhow::Result<(TestVector, ResolutionScenario)> {
    let (builder, known_version_v) = build_active_ledger(params, rng)?;
    let did = builder.did().clone();
    let query = did.with_query_version_id(3).to_string();
    finish(
        "version-beyond-served",
        "Query for a versionId the VDR has not yet served: one fetch then error.",
        builder,
        &known_version_v,
        vec![StepInput {
            served_did_document_count: 2,
            did_query: query,
            resolution_options: DIDResolutionOptions::no_metadata(false),
        }],
    )
}

/// Every resolution-scenario definition in stable catalog order.
pub(crate) fn definitions() -> &'static [ResolutionScenarioDefinition] {
    const DEFINITIONS: &[ResolutionScenarioDefinition] = &[
        ResolutionScenarioDefinition {
            name: "cold-plain-did-no-metadata",
            description: "Cold plain-DID resolve with no metadata: one VDR fetch; document not local; metadata vacuous.",
            factory: cold_plain_did_no_metadata,
        },
        ResolutionScenarioDefinition {
            name: "warm-version-id",
            description: "After a cold fetch, versionId query resolves locally with zero VDR requests.",
            factory: warm_version_id,
        },
        ResolutionScenarioDefinition {
            name: "warm-self-hash",
            description: "After a cold fetch, selfHash query resolves locally with zero VDR requests.",
            factory: warm_self_hash,
        },
        ResolutionScenarioDefinition {
            name: "warm-both-params",
            description: "After a cold fetch, agreeing selfHash and versionId query params resolve locally.",
            factory: warm_both_params,
        },
        ResolutionScenarioDefinition {
            name: "conflicting-query-params",
            description: "Disagreeing versionId and selfHash query params error without a VDR fetch when local.",
            factory: conflicting_query_params,
        },
        ResolutionScenarioDefinition {
            name: "plain-did-always-fetches",
            description: "Warm plain-DID resolve still fetches from the VDR when the latest-known doc is not deactivated.",
            factory: plain_did_always_fetches,
        },
        ResolutionScenarioDefinition {
            name: "request-creation-cold",
            description: "Cold plain-DID resolve with requestCreate fetches and populates creation metadata.",
            factory: request_creation_cold,
        },
        ResolutionScenarioDefinition {
            name: "request-creation-warm",
            description: "Warm versionId resolve with requestCreate is fully local (root already known).",
            factory: request_creation_warm,
        },
        ResolutionScenarioDefinition {
            name: "request-next-with-local-next",
            description: "Warm versionId resolve with requestNext when the next version is already local.",
            factory: request_next_with_local_next,
        },
        ResolutionScenarioDefinition {
            name: "request-next-at-latest",
            description: "Warm resolve of the latest version with requestNext requires a fetch to confirm next is absent.",
            factory: request_next_at_latest,
        },
        ResolutionScenarioDefinition {
            name: "request-latest-forces-fetch",
            description: "Warm versionId resolve with requestLatest forces a VDR fetch when not deactivated.",
            factory: request_latest_forces_fetch,
        },
        ResolutionScenarioDefinition {
            name: "request-deactivated-forces-fetch",
            description: "Warm versionId resolve with requestDeactivated forces a VDR fetch when not deactivated.",
            factory: request_deactivated_forces_fetch,
        },
        ResolutionScenarioDefinition {
            name: "deactivated-all-local",
            description: "After the deactivation tombstone is known, all metadata and plain-DID resolution succeed local-only.",
            factory: deactivated_all_local,
        },
        ResolutionScenarioDefinition {
            name: "local-only-matrix",
            description: "Local-only mode matrix: cold error; warm version-query success; warm plain-DID error; warm requestLatest error.",
            factory: local_only_matrix,
        },
        ResolutionScenarioDefinition {
            name: "incremental-range-fetch",
            description: "Step 1 serves one document; step 2 serves all and resolves latest via a single Range continuation.",
            factory: incremental_range_fetch,
        },
        ResolutionScenarioDefinition {
            name: "version-beyond-served",
            description: "Query for a versionId the VDR has not yet served: one fetch then error.",
            factory: version_beyond_served,
        },
    ];
    DEFINITIONS
}

/// Generate the complete resolution-scenario catalog.
pub(crate) fn generate(
    params: &TestVectorParams,
    global_seed: &str,
) -> anyhow::Result<Vec<(TestVector, ResolutionScenario)>> {
    definitions()
        .iter()
        .map(|definition| {
            (definition.factory)(
                params.clone(),
                DeterministicRng::for_vector(global_seed, definition.name),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn generate_all() -> Vec<(TestVector, ResolutionScenario)> {
        generate(
            &TestVectorParams::baseline("example.com"),
            "resolution-scenario-unit",
        )
        .expect("all resolution scenarios should generate")
    }

    #[test]
    fn catalog_names_are_unique_and_match_definitions() {
        let definition_v = definitions();
        let name_s = definition_v
            .iter()
            .map(|definition| definition.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(name_s.len(), definition_v.len());

        let pair_v = generate_all();
        assert_eq!(pair_v.len(), definition_v.len());
        for (definition, (vector, scenario)) in definition_v.iter().zip(pair_v.iter()) {
            assert_eq!(vector.name, definition.name);
            assert_eq!(scenario.name, definition.name);
            assert_eq!(vector.category, CATEGORY);
            assert!(vector.expected.is_fully_valid());
            assert_eq!(vector.did, scenario.did);
            assert!(!scenario.step_v.is_empty());
        }
    }

    #[test]
    fn microledgers_are_four_versions() {
        for (vector, scenario) in generate_all() {
            assert_eq!(
                vector.jsonl_line_v.len(),
                4,
                "{} should have ~4 versions",
                vector.name
            );
            assert_eq!(scenario.format, crate::RESOLUTION_SCENARIO_FORMAT);
        }
    }

    #[test]
    fn valid_from_timestamps_are_fractional_and_metadata_truncates() {
        use did_webplus_core::truncated_to_seconds;
        use std::collections::BTreeSet;

        let pair_v = generate_all();
        let mut millisecond_s = BTreeSet::new();
        let mut saw_creation_truncation = false;
        let mut saw_next_truncation = false;
        let mut saw_latest_truncation = false;

        for (vector, scenario) in &pair_v {
            let mut prev_valid_from_o = None;
            for line in &vector.jsonl_line_v {
                let doc: serde_json::Value = serde_json::from_str(line).expect("jsonl line");
                let valid_from_str = doc["validFrom"].as_str().expect("validFrom");
                assert!(
                    valid_from_str.contains('.'),
                    "{}: expected fractional validFrom, got {valid_from_str}",
                    vector.name
                );
                let valid_from = time::OffsetDateTime::parse(
                    valid_from_str,
                    &time::format_description::well_known::Rfc3339,
                )
                .expect("parse validFrom");
                assert!(
                    (1..=999).contains(&valid_from.millisecond()),
                    "{}: expected non-zero ms in {valid_from_str}",
                    vector.name
                );
                millisecond_s.insert(valid_from.millisecond() as u32);
                if let Some(prev) = prev_valid_from_o {
                    assert!(
                        valid_from > prev,
                        "{}: successive validFrom must be strictly increasing",
                        vector.name
                    );
                    assert_eq!(
                        truncated_to_seconds(valid_from) - truncated_to_seconds(prev),
                        time::Duration::seconds(1),
                        "{}: whole-seconds floor must advance by 1s",
                        vector.name
                    );
                }
                prev_valid_from_o = Some(valid_from);
            }

            for step in &scenario.step_v {
                let Some(meta) = step.expected.did_document_metadata_o.as_ref() else {
                    continue;
                };
                if let Some(creation) = meta.creation_metadata_o.as_ref() {
                    assert_eq!(
                        creation.creation_time(),
                        truncated_to_seconds(creation.creation_time_milliseconds())
                    );
                    assert_ne!(
                        creation.creation_time(),
                        creation.creation_time_milliseconds()
                    );
                    saw_creation_truncation = true;
                }
                if let Some(next) = meta.next_update_metadata_o.as_ref() {
                    assert_eq!(
                        next.next_update_time(),
                        truncated_to_seconds(next.next_update_time_milliseconds())
                    );
                    assert_ne!(
                        next.next_update_time(),
                        next.next_update_time_milliseconds()
                    );
                    saw_next_truncation = true;
                }
                if let Some(latest) = meta.latest_update_metadata_o.as_ref() {
                    assert_eq!(
                        latest.latest_update_time(),
                        truncated_to_seconds(latest.latest_update_time_milliseconds())
                    );
                    assert_ne!(
                        latest.latest_update_time(),
                        latest.latest_update_time_milliseconds()
                    );
                    saw_latest_truncation = true;
                }
            }
        }

        assert!(
            millisecond_s.len() >= 3,
            "expected variety of fractional milliseconds across scenarios, got {millisecond_s:?}"
        );
        assert!(saw_creation_truncation, "expected creation metadata truncation coverage");
        assert!(saw_next_truncation, "expected nextUpdate metadata truncation coverage");
        assert!(saw_latest_truncation, "expected updated metadata truncation coverage");
    }

    #[test]
    fn cold_plain_did_no_metadata_expectations() {
        let (_, scenario) = cold_plain_did_no_metadata(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("resolution-scenario-unit", "cold-plain-did-no-metadata"),
        )
        .unwrap();
        let step = &scenario.step_v[0];
        assert!(step.expected.success);
        assert_eq!(step.expected.vdr_request_count, 1);
        assert!(step.expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(!step.expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(
            step.expected
                .did_resolution_metadata
                .did_document_metadata_resolved_locally
        );
    }

    #[test]
    fn warm_query_steps_are_local_only() {
        for name in ["warm-version-id", "warm-self-hash", "warm-both-params"] {
            let definition = definitions()
                .iter()
                .find(|definition| definition.name == name)
                .unwrap();
            let (_, scenario) = (definition.factory)(
                TestVectorParams::baseline("example.com"),
                DeterministicRng::for_vector("resolution-scenario-unit", name),
            )
            .unwrap();
            assert_eq!(scenario.step_v.len(), 2);
            let warm = &scenario.step_v[1];
            assert!(warm.expected.success, "{name}");
            assert_eq!(warm.expected.vdr_request_count, 0, "{name}");
            assert!(
                warm.expected
                    .did_resolution_metadata
                    .did_document_resolved_locally,
                "{name}"
            );
        }
    }

    #[test]
    fn conflicting_query_params_errors_locally() {
        let (_, scenario) = conflicting_query_params(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("resolution-scenario-unit", "conflicting-query-params"),
        )
        .unwrap();
        let step = &scenario.step_v[1];
        assert!(!step.expected.success);
        assert_eq!(step.expected.vdr_request_count, 0);
        assert!(step.expected.did_resolution_metadata.error_o.is_some());
    }

    #[test]
    fn plain_did_always_fetches_on_warm_second_step() {
        let (_, scenario) = plain_did_always_fetches(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("resolution-scenario-unit", "plain-did-always-fetches"),
        )
        .unwrap();
        let step = &scenario.step_v[1];
        assert!(step.expected.success);
        assert_eq!(step.expected.vdr_request_count, 1);
        assert!(step.expected.did_resolution_metadata.fetched_updates_from_vdr);
        assert!(!step.expected.did_resolution_metadata.did_document_resolved_locally);
    }

    #[test]
    fn deactivated_all_local_second_step_is_local_only() {
        let (_, scenario) = deactivated_all_local(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("resolution-scenario-unit", "deactivated-all-local"),
        )
        .unwrap();
        let step = &scenario.step_v[1];
        assert!(step.expected.success);
        assert_eq!(step.expected.vdr_request_count, 0);
        assert!(step.resolution_options.local_resolution_only);
        assert_eq!(
            step.expected
                .did_document_metadata_o
                .as_ref()
                .unwrap()
                .deactivated_o,
            Some(true)
        );
    }

    #[test]
    fn local_only_matrix_covers_cold_warm_and_errors() {
        let (_, scenario) = local_only_matrix(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("resolution-scenario-unit", "local-only-matrix"),
        )
        .unwrap();
        assert_eq!(scenario.step_v.len(), 5);
        // Cold local-only error.
        assert!(!scenario.step_v[0].expected.success);
        assert_eq!(scenario.step_v[0].expected.vdr_request_count, 0);
        // Priming fetch.
        assert!(scenario.step_v[1].expected.success);
        assert_eq!(scenario.step_v[1].expected.vdr_request_count, 1);
        // Warm version-query success.
        assert!(scenario.step_v[2].expected.success);
        assert_eq!(scenario.step_v[2].expected.vdr_request_count, 0);
        // Warm plain-DID error.
        assert!(!scenario.step_v[3].expected.success);
        assert_eq!(scenario.step_v[3].expected.vdr_request_count, 0);
        // Warm requestLatest error.
        assert!(!scenario.step_v[4].expected.success);
        assert_eq!(scenario.step_v[4].expected.vdr_request_count, 0);
        assert!(
            scenario.step_v[4]
                .expected
                .did_resolution_metadata
                .did_document_resolved_locally
        );
        assert!(
            !scenario.step_v[4]
                .expected
                .did_resolution_metadata
                .did_document_metadata_resolved_locally
        );
    }

    #[test]
    fn incremental_range_fetch_two_single_requests() {
        let (_, scenario) = incremental_range_fetch(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("resolution-scenario-unit", "incremental-range-fetch"),
        )
        .unwrap();
        assert_eq!(scenario.step_v[0].served_did_document_count, 1);
        assert_eq!(scenario.step_v[0].expected.did_document_version_id_o, Some(0));
        assert_eq!(scenario.step_v[0].expected.vdr_request_count, 1);
        assert_eq!(scenario.step_v[1].served_did_document_count, 4);
        assert_eq!(scenario.step_v[1].expected.did_document_version_id_o, Some(3));
        assert_eq!(scenario.step_v[1].expected.vdr_request_count, 1);
    }

    #[test]
    fn version_beyond_served_fetches_then_errors() {
        let (_, scenario) = version_beyond_served(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("resolution-scenario-unit", "version-beyond-served"),
        )
        .unwrap();
        let step = &scenario.step_v[0];
        assert!(!step.expected.success);
        assert_eq!(step.expected.vdr_request_count, 1);
        assert!(step.expected.did_resolution_metadata.fetched_updates_from_vdr);
    }

    #[test]
    fn request_next_at_latest_fetches_to_confirm_absence() {
        let (_, scenario) = request_next_at_latest(
            TestVectorParams::baseline("example.com"),
            DeterministicRng::for_vector("resolution-scenario-unit", "request-next-at-latest"),
        )
        .unwrap();
        let step = &scenario.step_v[1];
        assert!(step.expected.success);
        assert_eq!(step.expected.vdr_request_count, 1);
        assert!(step.expected.did_resolution_metadata.did_document_resolved_locally);
        assert!(
            !step
                .expected
                .did_resolution_metadata
                .did_document_metadata_resolved_locally
        );
        assert!(
            step.expected
                .did_document_metadata_o
                .as_ref()
                .unwrap()
                .next_update_metadata_o
                .is_none()
        );
    }
}
