//! Deterministic generation of did:webplus test-vector microledgers.
//!
//! This crate holds the catalog factories, metadata/index schemas, and filesystem
//! writer used by the `did-webplus-test-vector` CLI. With the `server` feature it also
//! provides an axum HTTP service ([`spawn_test_vector_server`]) that eagerly generates
//! the catalog into memory and serves `index.json`, `did-documents.jsonl` (with HTTP
//! `Range`), `test-vector.json`, and (for the resolution-scenario category)
//! `resolution-scenario.json`, plus harness control endpoints. Callers own I/O policy:
//! the library returns [`TestVector`] values, can write a statically servable tree via
//! [`TestVectorWriter`], or can serve the same layout over HTTP.
//!
//! # Purpose
//!
//! Produce a reusable, deterministically regenerable catalog of microledgers that
//! exercise DID-document validation, crypto/path coverage, JSONL edge cases, stateful
//! resolution / metadata / local-only scenarios, bounded stress, and seeded
//! single-field mutations. Each vector has its own DID, a `did-documents.jsonl` body,
//! and authoritative expectation metadata in `test-vector.json`. Resolution-scenario
//! vectors also carry [`ResolutionScenario`] in `resolution-scenario.json`. Harnesses
//! discover vectors through a derived `index.json` at the target-dir root.
//!
//! Harness-facing summary lives in the `did-webplus-test-vector` crate README; this
//! module is the authoritative design document (schema, oracle, determinism,
//! control-endpoint contract).
//!
//! # Determinism model
//!
//! ## Catalog vectors (conformance, coverage-matrix, jsonl-structural, resolution-scenario, stress)
//!
//! A global CLI `--seed` string plus the stable vector **name** derive a per-vector
//! [`DeterministicRng`]:
//!
//! ```text
//! ChaCha20 seed = BLAKE3(global_seed || vector_name)
//! ```
//!
//! Keys, timestamps, and thus the DID (root self-hash) are independent of catalog
//! order: adding or reordering other vectors never changes an existing name's DID.
//!
//! Timestamps start from [`TIMESTAMP_BASE`] (`2025-01-01T00:00:00Z`) with
//! [`TIMESTAMP_INCREMENT`] whole-second steps. Resolution-scenario microledgers
//! additionally enable [`DeterministicRng::with_fractional_timestamps`], so each
//! `validFrom` carries a deterministic non-zero millisecond component (`1..=999`)
//! derived from the timestamp index. Expected
//! [`did_webplus_core::DIDDocumentMetadata`] values therefore include concrete
//! `*Milliseconds` fields and whole-seconds counterparts that are the floor of
//! those millisecond timestamps — regenerable from the same seed, not relative
//! placeholders.
//!
//! ## Fuzz-lite vectors
//!
//! Names are qualified so multiple campaigns can coexist under one host:
//!
//! ```text
//! fuzz-lite-<seed_hex>-{index:05}
//! ```
//!
//! where `seed_hex` is the **full** lowercase hex encoding of the CLI `--seed`
//! string's UTF-8 bytes (not a truncated hash). The original seed string is still
//! stored in `test-vector.json` as `generator.seed`. When validating or rebuilding,
//! that field must match the seed decoded from the name
//! ([`TestVectorMetadata::validate_fuzz_lite_seed`]).
//!
//! **RNG rule (no double-hashing):** the final vector name already embeds the seed,
//! so the RNG is bound only to that name — e.g.
//! `DeterministicRng::for_vector("", name)` / `BLAKE3(name)`. Do **not** also pass
//! the CLI seed into `for_vector(cli_seed, full_name)` when `full_name` already
//! contains that seed.
//!
//! Seed-first naming keeps one campaign contiguous in sorted `groups.fuzz-lite`
//! lists; fixed-width `{index:05}` keeps lexicographic order aligned with numeric
//! order within a campaign.
//!
//! # Categories
//!
//! | Category | What it exercises |
//! |----------|-------------------|
//! | `conformance` | Positive/negative pairs for DID-document validation rules (each negative breaks exactly one rule) |
//! | `coverage-matrix` | Key types × hash functions, both multibase bases, mixed-history and path variants |
//! | `jsonl-structural` | Empty files, blank lines, CRLF, duplicate/trailing garbage, valid-prefix-then-invalid |
//! | `resolution` | Valid microledgers whose [`TestVector::did`] / served path disagrees with the DID inside `did-documents.jsonl` (host, path, or root self-hash) |
//! | `resolution-scenario` | Stateful resolution / metadata / local-only scenarios (`resolution-scenario.json` beside a fully valid body); see [`ResolutionScenario`] |
//! | `stress` | Bounded large histories / documents / nesting / proofs / DID paths (sizes via [`StressConfig`]) |
//! | `fuzz-lite` | Seeded structured single-field mutations with computed expectations |
//!
//! Cheap listing ([`Catalog::list`] / [`CatalogListRequest`]) returns
//! name/category/description/positive for the full catalog without generating
//! keys or microledgers (used by CLI `--dry-run`). Size knobs are
//! `fuzz_lite_count` (`0` omits fuzz-lite) and stress config / seed.
//!
//! # On-disk layout and serving
//!
//! A single hostname+port is generated per invocation, so there is no
//! `<hostname>[:<port>]` directory. `--target-dir` is the directory that already
//! corresponds to `--did-path` on the serving host. For a DID such as
//! `did:webplus:example.com%3A3000:tv:demo:<root-self-hash>` with
//! `--did-path tv:demo` and `--target-dir ./out`:
//!
//! ```text
//! ./out/                           # --target-dir (== served --did-path location)
//!   index.json                     # derived discovery (v2); rebuilt from tree
//!   <root-self-hash>/
//!     did-documents.jsonl
//!     test-vector.json             # authoritative expectations
//!     [resolution-scenario.json]   # resolution-scenario category only
//!   teams/identity/alice/<hash>/   # extra path components under --did-path
//! ```
//!
//! Point a static file server at the parent of `--did-path` (or otherwise map
//! URLs so `/{did-path}/...` reaches `--target-dir`) so clients can fetch
//! `index.json`, `<path>/did-documents.jsonl`, and `<path>/test-vector.json`.
//! Port presence in DIDs comes only from the CLI `--port` flag.
//!
//! **Static hosting caveat:** a static Range-capable catalog may ship
//! `resolution-scenario.json` for discovery, but scenario *conformance* (mutating
//! serve-count and asserting `vdrRequestCount`) requires the live HTTP service
//! below — control endpoints cannot work on static hosting.
//!
//! # `test-vector.json` (authoritative)
//!
//! Format: [`TEST_VECTOR_FORMAT`] (`did-webplus-test-vector/1`). See
//! [`TestVectorMetadata`].
//!
//! - **Normative for harnesses:** `expected.validDidDocumentCount` (and thus
//!   `expected.valid`). Fully valid ⇒ count equals `didDocumentCount`; root
//!   invalid ⇒ `0`; otherwise the first `validDidDocumentCount` lines must be
//!   accepted and the next (if any) rejected.
//! - **Advisory:** `expected.errorCode` / `expected.errorVersionId` — taxonomy
//!   for docs and harnesses; other implementations need not match codes exactly.
//! - **`generator.seed`:** the original CLI `--seed` string (human-readable), not
//!   the hex form embedded in fuzz-lite names.
//!
//! # `resolution-scenario.json` (authoritative for scenario harnesses)
//!
//! Format: [`RESOLUTION_SCENARIO_FORMAT`] (`did-webplus-resolution-scenario/1`).
//! See [`ResolutionScenario`], [`ResolutionStep`], [`ExpectedResolutionOutcome`].
//!
//! Schema sketch:
//!
//! ```json
//! {
//!   "format": "did-webplus-resolution-scenario/1",
//!   "name": "<catalog-name>",
//!   "description": "...",
//!   "specRef": ["..."],
//!   "did": "<did>",
//!   "steps": [
//!     {
//!       "servedDidDocumentCount": 3,
//!       "didQuery": "<did-url>",
//!       "resolutionOptions": {
//!         "requestCreate": false,
//!         "requestNext": false,
//!         "requestLatest": false,
//!         "requestDeactivated": false,
//!         "localResolutionOnly": false
//!       },
//!       "expected": {
//!         "success": true,
//!         "didDocumentVersionId": 2,
//!         "didDocumentSelfHash": "uEiB...",
//!         "didDocumentMetadata": { "...": "..." },
//!         "didResolutionMetadata": {
//!           "contentType": "application/did+json",
//!           "fetchedUpdatesFromVDR": true,
//!           "didDocumentResolvedLocally": false,
//!           "didDocumentMetadataResolvedLocally": true
//!         },
//!         "vdrRequestCount": 1
//!       }
//!     }
//!   ]
//! }
//! ```
//!
//! **Preconditions:** empty DID doc store per scenario; store persists across
//! ordered steps; `servedDidDocumentCount` is monotonically non-decreasing.
//!
//! **Normative expectations:** per-step success/failure; on success, document
//! identity and byte-exact `didDocumentMetadata`; exact resolution-metadata
//! booleans; exact `vdrRequestCount` (`0` = local-only, `1` = single Range fetch).
//! On failure, `didResolutionMetadata.error` present-only (message advisory).
//!
//! # Resolution-semantics oracle
//!
//! [`ResolutionSemantics`] is a pure model of full-resolver locality, metadata
//! population, and resolution-metadata booleans. The scenario catalog fills
//! [`ExpectedResolutionOutcome`] via this oracle so expectations stay consistent
//! with the draft normative rules documented on that type. Unit tests pin the
//! oracle; the resolver integration harness pins the Rust implementation against
//! the published scenario vectors.
//!
//! # `index.json` v2 (derived discovery)
//!
//! Format: [`TEST_VECTOR_INDEX_FORMAT`] (`did-webplus-test-vector-index/2`). See
//! [`TestVectorIndex`].
//!
//! ```json
//! {
//!   "format": "did-webplus-test-vector-index/2",
//!   "vectors": {
//!     "<name>": { "did": "<did>", "path": "<relative-dir>" }
//!   },
//!   "groups": {
//!     "positive": ["..."],
//!     "negative": ["..."],
//!     "conformance": ["..."],
//!     "coverage-matrix": ["..."],
//!     "jsonl-structural": ["..."],
//!     "resolution": ["..."],
//!     "resolution-scenario": ["..."],
//!     "stress": ["..."],
//!     "fuzz-lite": ["..."]
//!   }
//! }
//! ```
//!
//! `path` is target-dir-relative, `/`-separated, and names the directory containing
//! `did-documents.jsonl` and `test-vector.json` (no `..`). The configured `--did-path`
//! prefix is already represented by `target_dir` and is not repeated in `path`.
//! Resolution-scenario vectors are body-positive (also listed under `positive`);
//! the `resolution-scenario` group distinguishes them for scenario harnesses.
//! Plain black-box `resolve(did)`-latest harnesses may treat them as ordinary
//! positive vectors; full scenario conformance requires a scenario runner plus
//! the live control API.
//!
//! **Invariants** (enforced by [`TestVectorIndex::build`]):
//!
//! 1. Every name listed in any group exists in `vectors`.
//! 2. Every vector is in exactly one of `positive` / `negative`.
//! 3. Every vector is in the group named after its category.
//! 4. Maps/lists are sorted (`BTreeMap`; sorted `Vec`s).
//! 5. Duplicate names across the tree are an error.
//!
//! **Rebuild-from-tree:** [`TestVectorWriter::write_all`] writes vectors then
//! rebuilds `index.json` by scanning for `test-vector.json`
//! (not "index = only this invocation"). If a rewritten name already exists at a
//! different DID path, the old vector directory is removed first.
//! [`TestVectorWriter::rebuild_indexes_under`] / [`TestVectorWriter::rebuild_index`]
//! scan the tree as-is (CLI `rebuild-index`). New vectors can be added and the
//! index recreated without regenerating the whole dataset.
//!
//! # How a harness should consume the catalog
//!
//! 1. Fetch `index.json` from the served `--did-path` / `--target-dir` location.
//! 2. Select a group (`positive`, `negative`, or a category key).
//! 3. For each name, resolve `vectors[name].path` (and optionally `did`).
//! 4. Fetch `.../<path>/did-documents.jsonl` and `.../<path>/test-vector.json`.
//! 5. Validate the accept/reject boundary against
//!    `expected.validDidDocumentCount` / `expected.valid` (normative). Treat
//!    error codes as advisory.
//! 6. For `resolution` vectors, also require that the DID derived from the
//!    serving host + `path` (i.e. `vectors[name].did`) equals the DID inside
//!    `did-documents.jsonl`. Those bodies are fully valid alone; rejection is
//!    relative to the resolution URL (see VDR create/update checks).
//! 7. For `resolution-scenario` vectors: fetch `resolution-scenario.json`; for
//!    each step against a fresh-then-persistent store, set serve-count via the
//!    control API, resolve with the step's options, and assert normative
//!    expectations including `vdrRequestCount` (requires live `serve`, not
//!    static hosting).
//!
//! # CLI relationship
//!
//! The `did-webplus-test-vector` binary is a thin clap front-end:
//!
//! - `generate` — full catalog via [`Catalog::generate_with_progress`];
//!   `--dry-run` uses [`Catalog::list`]; `--fuzz-lite-count` sizes fuzz-lite
//!   (`0` skips); writes via [`TestVectorWriter::write_all`] (including
//!   `resolution-scenario.json`).
//! - `rebuild-index` — [`TestVectorWriter::rebuild_indexes_under`].
//! - `serve` — [`spawn_test_vector_server`] (requires the `server` feature): eager
//!   in-memory catalog + HTTP origin matching the V1 URL layout, plus control
//!   endpoints for scenario harnesses.
//!
//! Design detail lives here; the binary docs stay thin and point at this module.
//!
//! # V2 HTTP service (`server` feature)
//!
//! [`spawn_test_vector_server`] binds an axum service that eagerly materializes the
//! catalog (same generators as V1) into [`TestVectorServerAppState`] and serves:
//!
//! - `GET /health`
//! - `GET /index.json` (or `/{did-path}/index.json` when `--did-path` is set)
//! - `GET /{…}/did-documents.jsonl` with HTTP `Range` (206 / 416 `bytes */N`);
//!   body length follows the current per-vector serve-count (default: all lines)
//! - `GET /{…}/test-vector.json`
//! - `GET /{…}/resolution-scenario.json` (resolution-scenario vectors only)
//!
//! ## Control-endpoint contract
//!
//! Harness-only routes outside the DID resolution namespace. Paths are vector
//! directory request paths (no leading `/`, no filename), matching
//! [`TestVectorIndexRecord`] / `index.json` `path` values and the URL directory
//! used to fetch `did-documents.jsonl`.
//!
//! | Method | Path | Body / query | Success |
//! |--------|------|--------------|---------|
//! | `PUT` | `/control/serve-count` | [`ServeCountControlRequest`] (`path`, `servedDidDocumentCount`) | [`ServeCountControlResponse`] (`path`, `servedDidDocumentCount`, `servedOctetLength`) |
//! | `GET` | `/control/request-count` | `?path=…` | [`RequestCountControlResponse`] (`path`, `requestCount`) |
//! | `POST` | `/control/reset` | (none) | `204 No Content` — restore every vector to full serve-count and zero jsonl GET counters |
//!
//! Per-step harness order: `POST /control/reset`, then `PUT /control/serve-count`
//! for the step's count, then resolve, then `GET /control/request-count` and
//! assert equals `expected.vdrRequestCount`. Unknown paths → `404`;
//! `servedDidDocumentCount` above the vector's document count → `400`.
//!
//! Size caps are existing [`StressConfig`] knobs and `fuzz_lite_count`. True
//! streaming generation without materializing stress bodies remains deferred.
//!
//! ## Harness note: black-box resolve vs incremental self-check
//!
//! Library self-check tests assert line-by-line `validDidDocumentCount`.
//! Resolvers fetch the whole JSONL and validate all-or-nothing. Black-box
//! resolver compliance should treat `resolve(did)` as success iff
//! `expected.valid` (equivalently `groups.positive`), not assert exact
//! accept-prefix counts via resolve.

mod base_choice;
mod catalog;
mod catalog_generation;
mod conformance_catalog;
mod coverage_matrix_catalog;
mod deterministic_rng;
mod error_code;
mod expected;
mod expected_resolution_outcome;
mod fuzz_lite_catalog;
mod hash_function_choice;
mod jsonl_structural_catalog;
mod key_type_choice;
mod known_did_document_version;
mod microledger_builder;
mod raw_did_document;
mod resolution_catalog;
mod resolution_scenario;
mod resolution_scenario_catalog;
mod resolution_semantics;
mod resolution_step;
mod resolver_state;
mod stress_catalog;
mod stress_config;
mod structured_mutation;
mod test_vector;
mod test_vector_index;
mod test_vector_metadata;
mod test_vector_params;
mod test_vector_writer;

#[cfg(feature = "server")]
mod request_count_control_response;
#[cfg(feature = "server")]
mod serve_count_control_request;
#[cfg(feature = "server")]
mod serve_count_control_response;
#[cfg(feature = "server")]
mod spawn_test_vector_server;
#[cfg(feature = "server")]
mod test_vector_server_app_state;
#[cfg(feature = "server")]
mod test_vector_server_config;
#[cfg(feature = "server")]
mod test_vector_server_routes;
#[cfg(feature = "server")]
mod test_vector_server_vector_runtime;

pub use crate::{
    base_choice::BaseChoice,
    catalog::{Catalog, CatalogDescriptor, CatalogListRequest, VectorDefinition},
    catalog_generation::CatalogGeneration,
    deterministic_rng::{DeterministicRng, TIMESTAMP_BASE, TIMESTAMP_INCREMENT},
    error_code::ErrorCode,
    expected::Expected,
    expected_resolution_outcome::ExpectedResolutionOutcome,
    hash_function_choice::HashFunctionChoice,
    key_type_choice::KeyTypeChoice,
    known_did_document_version::KnownDidDocumentVersion,
    microledger_builder::MicroledgerBuilder,
    raw_did_document::RawDidDocument,
    resolution_scenario::{
        RESOLUTION_SCENARIO_CATEGORY, RESOLUTION_SCENARIO_FORMAT, ResolutionScenario,
    },
    resolution_scenario_catalog::ResolutionScenarioDefinition,
    resolution_semantics::{ResolutionSemantics, ResolutionStepPrediction},
    resolution_step::ResolutionStep,
    resolver_state::ResolverState,
    stress_config::StressConfig,
    structured_mutation::{MutationTarget, StructuredMutation},
    test_vector::TestVector,
    test_vector_index::{
        NEGATIVE_GROUP_NAME, POSITIVE_GROUP_NAME, TEST_VECTOR_INDEX_FORMAT, TestVectorIndex,
        TestVectorIndexRecord, TestVectorLocation,
    },
    test_vector_metadata::{
        ExpectedSummary, GENERATOR_NAME, GeneratorInfo, TEST_VECTOR_FORMAT, TestVectorMetadata,
    },
    test_vector_params::TestVectorParams,
    test_vector_writer::{
        DID_DOCUMENTS_JSONL_FILENAME, INDEX_JSON_FILENAME, RESOLUTION_SCENARIO_JSON_FILENAME,
        TEST_VECTOR_JSON_FILENAME, TestVectorWriter,
    },
};

#[cfg(feature = "server")]
pub use crate::{
    request_count_control_response::RequestCountControlResponse,
    serve_count_control_request::ServeCountControlRequest,
    serve_count_control_response::ServeCountControlResponse,
    spawn_test_vector_server::spawn_test_vector_server,
    test_vector_server_app_state::{
        ServeCountError, TestVectorServerAppState, TestVectorServerVectorBodies,
    },
    test_vector_server_config::TestVectorServerConfig,
    test_vector_server_vector_runtime::TestVectorServerVectorRuntime,
};

/// Package name, suitable for embedding in generated `test-vector.json` metadata.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

/// Package version, suitable for embedding in generated `test-vector.json` metadata.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default global seed so published DIDs stay stable across runs.
///
/// Shared by the CLI (`--seed` default) and library self-check tests so both
/// exercise the same deterministic catalog.
pub const DEFAULT_SEED: &str = "did-webplus-test-vector-v1";

/// Default global number of fuzz-lite vectors.
pub const DEFAULT_FUZZ_LITE_COUNT: u32 = 128;
