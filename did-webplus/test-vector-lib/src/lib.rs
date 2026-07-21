//! Deterministic generation of did:webplus test-vector microledgers.
//!
//! This crate holds the catalog factories, metadata/index schemas, and filesystem
//! writer used by the `did-webplus-test-vector` CLI and (later) by a V2 web service.
//! Callers own I/O policy: the library returns [`TestVector`] values and can write a
//! statically servable tree via [`TestVectorWriter`].
//!
//! # Purpose
//!
//! Produce a reusable, deterministically regenerable catalog of microledgers that
//! exercise DID-document validation, crypto/path coverage, JSONL edge cases, bounded
//! stress, and seeded single-field mutations. Each vector has its own DID, a
//! `did-documents.jsonl` body, and authoritative expectation metadata in
//! `test-vector.json`. Harnesses discover vectors through a derived
//! `index.json` at the target-dir root.
//!
//! # Determinism model
//!
//! ## Catalog vectors (conformance, coverage-matrix, jsonl-structural, stress)
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
//! | `stress` | Bounded large histories / documents / nesting / proofs / DID paths (sizes via [`StressConfig`]) |
//! | `fuzz-lite` | Seeded structured single-field mutations with computed expectations |
//!
//! Cheap listing ([`Catalog::list`] / [`CatalogListRequest`]) returns
//! name/category/description/positive for the full catalog without generating
//! keys or microledgers (used by CLI `--dry-run`). Size knobs are only
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
//!   teams/identity/alice/<hash>/   # extra path components under --did-path
//! ```
//!
//! Point a static file server at the parent of `--did-path` (or otherwise map
//! URLs so `/{did-path}/...` reaches `--target-dir`) so clients can fetch
//! `index.json`, `<path>/did-documents.jsonl`, and `<path>/test-vector.json`.
//! Port presence in DIDs comes only from the CLI `--port` flag.
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
//!     "stress": ["..."],
//!     "fuzz-lite": ["..."]
//!   }
//! }
//! ```
//!
//! `path` is target-dir-relative, `/`-separated, and names the directory containing
//! `did-documents.jsonl` and `test-vector.json` (no `..`). The configured `--did-path`
//! prefix is already represented by `target_dir` and is not repeated in `path`.
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
//! (not "index = only this invocation"). [`TestVectorWriter::rebuild_indexes_under`]
//! / [`TestVectorWriter::rebuild_index`] do the same (CLI `rebuild-index`). New
//! vectors can be added and the index recreated without regenerating the whole
//! dataset.
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
//!
//! # CLI relationship
//!
//! The `did-webplus-test-vector` binary is a thin clap front-end:
//!
//! - `generate` — full catalog via [`Catalog::generate_with_progress`];
//!   `--dry-run` uses [`Catalog::list`]; `--fuzz-lite-count` sizes fuzz-lite
//!   (`0` skips); writes via [`TestVectorWriter::write_all`].
//! - `rebuild-index` — [`TestVectorWriter::rebuild_indexes_under`].
//!
//! Design detail lives here; the binary docs stay thin and point at this module.
//!
//! # V2 service sketch (deferred)
//!
//! A future HTTP service would generate and stream vectors on demand from the same
//! `(seed, name, params)` determinism, with procedural metadata/index and optional
//! streaming JSONL / `Range` for large stress histories. Open items include
//! root-self-hash discovery before the client names it, rate limits, and encoding
//! of stress size parameters.

mod base_choice;
mod catalog;
mod conformance_catalog;
mod coverage_matrix_catalog;
mod deterministic_rng;
mod error_code;
mod expected;
mod fuzz_lite_catalog;
mod hash_function_choice;
mod jsonl_structural_catalog;
mod key_type_choice;
mod microledger_builder;
mod raw_did_document;
mod resolution_catalog;
mod stress_catalog;
mod stress_config;
mod structured_mutation;
mod test_vector;
mod test_vector_index;
mod test_vector_metadata;
mod test_vector_params;
mod test_vector_writer;

pub use crate::{
    base_choice::BaseChoice,
    catalog::{Catalog, CatalogDescriptor, CatalogListRequest, VectorDefinition},
    deterministic_rng::{DeterministicRng, TIMESTAMP_BASE, TIMESTAMP_INCREMENT},
    error_code::ErrorCode,
    expected::Expected,
    hash_function_choice::HashFunctionChoice,
    key_type_choice::KeyTypeChoice,
    microledger_builder::MicroledgerBuilder,
    raw_did_document::RawDidDocument,
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
        DID_DOCUMENTS_JSONL_FILENAME, INDEX_JSON_FILENAME, TEST_VECTOR_JSON_FILENAME,
        TestVectorWriter,
    },
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
