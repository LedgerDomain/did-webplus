# did-webplus-test-vector

CLI and supporting library for generating a deterministic, statically servable catalog of `did:webplus` test-vector microledgers.

Each vector has its own DID, on-disk directory, JSONL microledger (`did-documents.jsonl`), and machine-readable expectation metadata (`test-vector.json`). Harnesses discover vectors via `index.json` at the `--target-dir` root (derived discovery; metadata remains authoritative).

Generation logic and full design docs live in [`did-webplus-test-vector-lib`](../test-vector-lib) (crate-level module docs in `src/lib.rs`). This crate is a thin clap binary over that library.

## Purpose

Produce reusable test vectors that exercise:

- **Conformance** — positive/negative pairs for DID-document validation rules (each negative breaks exactly one rule)
- **Coverage matrix** — key types × hash functions, both multibase bases, mixed-history and path variants
- **JSONL structural** — empty files, blank lines, CRLF, duplicate/trailing garbage lines, valid-prefix-then-invalid
- **Resolution** — valid microledgers whose resolution DID / served path disagrees with the DID inside `did-documents.jsonl` (host, port, path, or root self-hash)
- **Stress** — bounded large histories / documents / nesting / proofs / DID paths (sizes CLI-configurable)
- **Fuzz-lite** — seeded structured single-field mutations with computed expectations (count via `--fuzz-lite-count`; `0` skips)

Vectors are deterministic: a global seed plus vector name derives a per-vector RNG (fuzz-lite embeds the seed in the name and binds the RNG to that final name only). Published DIDs stay stable when the catalog grows.

There is no `verify` subcommand; verification against a reference store is covered by the library's integration tests and by external harnesses.

## Building and installing

From this directory (or the workspace root):

```bash
cargo install --path .
```

Or run without installing:

```bash
cargo run -p did-webplus-test-vector -- <subcommand> ...
```

Environment variables use the `DID_WEBPLUS_TEST_VECTOR_*` prefix (clap `env`). A `.env` file is loaded via `dotenvy` when present.

## CLI usage

Subcommands: `generate` and `rebuild-index`.

### Shared `generate` options

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--host <HOST>` | `DID_WEBPLUS_TEST_VECTOR_HOST` | *(required)* | DID hostname (e.g. `example.com`, `localhost`) |
| `--port <PORT>` | `DID_WEBPLUS_TEST_VECTOR_PORT` | *(none)* | Optional DID port (`%3A<port>` in the DID); sole control of port presence |
| `--did-path <p1:p2>` | `DID_WEBPLUS_TEST_VECTOR_DID_PATH` | *(none)* | Colon-separated DID path; `target-dir` is the on-disk location for that path |
| `--target-dir <DIR>` | `DID_WEBPLUS_TEST_VECTOR_TARGET_DIR` | `.` | Output root for vectors and `index.json` (no hostname subdirectory) |
| `--seed <STRING>` | `DID_WEBPLUS_TEST_VECTOR_SEED` | `did-webplus-test-vector-v1` | Global seed for deterministic RNG |
| `--stress-versions <N,...>` | `DID_WEBPLUS_TEST_VECTOR_STRESS_VERSIONS` | `100,1000` | Override stress many-versions tiers |

### `generate`

Always writes **all** categories: conformance, coverage-matrix, jsonl-structural, resolution, stress, and fuzz-lite. Progress goes to stderr. After writing, `index.json` under `--target-dir` is **rebuilt from every on-disk `test-vector.json`** (pre-existing vectors remain in the index).

```bash
did-webplus-test-vector generate \
  --host example.com \
  --port 3000 \
  --did-path tv:demo \
  --target-dir ./out
```

For hosting at a real domain path (e.g. GitHub Pages), set `--target-dir` to the directory that will be served at `--did-path`:

```bash
cargo run -p did-webplus-test-vector -- generate \
  --target-dir ../did-webplus-spec/test-vector \
  --host ledgerdomain.github.io \
  --did-path did-webplus-spec:test-vector
```

Additional options:

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--dry-run` | `DID_WEBPLUS_TEST_VECTOR_DRY_RUN` | off | Print planned vectors; no file I/O, no crypto/generation |
| `--fuzz-lite-count <N>` | `DID_WEBPLUS_TEST_VECTOR_FUZZ_LITE_COUNT` | `128` | Fuzz-lite count; `0` skips fuzz-lite |

Dry-run (tab-separated: `name`, `category`, `positive|negative`, `description`):

```bash
did-webplus-test-vector generate --host example.com --dry-run
```

### `rebuild-index`

Walk `--target-dir`, find every `test-vector.json`, and rebuild `index.json` at the target-dir root from that authoritative metadata.

```bash
did-webplus-test-vector rebuild-index --target-dir ./out
```

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--target-dir <DIR>` | `DID_WEBPLUS_TEST_VECTOR_TARGET_DIR` | `.` | Root to scan |

## Directory layout and serving

A single hostname+port is generated per invocation, so there is no `<hostname>[:<port>]` subdirectory. `--target-dir` is the directory that already corresponds to `--did-path` on the serving host.

Layout for a DID such as
`did:webplus:example.com%3A3000:tv:demo:<root-self-hash>` with `--did-path tv:demo` and `--target-dir ./out`:

```text
./out/                           # --target-dir (== served --did-path location)
  index.json
  <root-self-hash>/
    did-documents.jsonl
    test-vector.json
  teams/identity/alice/<hash>/   # extra path components under --did-path
  path0000/.../<hash>/           # stress-long-did-path under --did-path
```

- `--did-path` components appear in every DID but are **not** re-created under `--target-dir`.
- Extra path components (coverage multi-path, stress long path) nest under `--target-dir`.
- Port presence in DIDs comes only from `--port` (no separate port test vectors).
- Each vector directory contains:
  - `did-documents.jsonl` — one DID document per line (JCS or deliberately non-JCS for negatives)
  - `test-vector.json` — authoritative metadata and expectations
- `index.json` at `--target-dir` lists **all** vectors found under that tree. `generate` rebuilds it after writing; use `rebuild-index` after adding or editing vectors by hand.

### Static HTTP serving

Serve so that the URL path for `--did-path` maps to `--target-dir`. For local testing with no DID path (`--host localhost --port 3000 --target-dir ./out`):

```bash
cd ./out && python3 -m RangeHTTPServer 3000
```

Then:

- `GET http://localhost:3000/index.json` lists vectors and groups
- `GET http://localhost:3000/<path>/did-documents.jsonl` serves the microledger
- `GET http://localhost:3000/<path>/test-vector.json` serves metadata

`path` is the `path` field from `index.json` `vectors` (forward-slash path under `--target-dir`).

A `did:webplus` DID resolver against this catalog: **positive** vectors must resolve successfully; **negative** vectors (including `resolution`) must fail.

#### A note on hostname and port for local hosting

On Linux (and probably Mac OS), it's possible to set up a hostname alias to point to the local loopback device (`127.0.0.1`, roughly equivalent to `localhost`).  Edit `/etc/hosts` and create an entry like

    127.0.0.1   example.com

This will cause the hostname `example.com` to resolve to the IP address `127.0.0.1` (which is the local loopback device).  This allows testing of non-`localhost` DIDs by serving local content.  However, be advised that it will be necessary to override `https` (the default for `did:webplus` DID resolution for non-`localhost` hostnames) with `http` in this case.

The default ports used in `did:webplus` DID resolution are `80` for `http` (which only applies to `localhost`) and `443` for `https` (for all other hostnames).  If it's desired to locally serve DIDs at either of these ports, either the hosting must be done by the superuser (all ports up to 1024 are privileged ports) or by forwarding the port to an unprivileged port at which a non-privileged user can serve the DIDs.  See [forward-port-80.sh](../../forward-port-80.sh) for more info.

## `index.json` schema (v2)

Format string: `did-webplus-test-vector-index/2`.

This file is **derived discovery** data. Expectations live only in `test-vector.json`.

```json
{
  "format": "did-webplus-test-vector-index/2",
  "vectors": {
    "root-valid": {
      "did": "did:webplus:example.com%3A3000:tv:demo:uHiB...",
      "path": "tv/demo/uHiB..."
    }
  },
  "groups": {
    "positive": ["root-valid", "..."],
    "negative": ["..."],
    "conformance": ["root-valid", "..."],
    "coverage-matrix": ["..."],
    "jsonl-structural": ["..."],
    "resolution": ["..."],
    "stress": ["..."],
    "fuzz-lite": ["..."]
  }
}
```

| Field | Meaning |
|-------|---------|
| `vectors` | Map of catalog name → `{ did, path }` (`path` is target-dir-relative, `/`-separated) |
| `groups.positive` / `groups.negative` | Every vector appears in exactly one validity group |
| `groups.<category>` | Every vector appears in its category group |

Invariants: every group member exists in `vectors`; maps and name lists are sorted; duplicate names in the target tree are an error.

### Harness consumption

1. Fetch `index.json`.
2. Select a group (`positive`, `negative`, or a category).
3. Resolve each name via `vectors[name].path`.
4. Fetch JSONL + `test-vector.json`.
5. Apply expectations (next section). Treat error codes as advisory.

**Black-box resolver:** resolve `vectors[name].did` — expect success iff `expected.valid` (equivalently: name is in `groups.positive`).

**Incremental validator:** for non-`resolution` vectors, assert the accept/reject prefix from `expected.validDidDocumentCount` (see below). For `resolution`, the JSONL body must fully validate on its own, but binding it to `vectors[name].did` / the served path must fail (`document.id` must equal that DID).

## `test-vector.json` schema

Format string: `did-webplus-test-vector/1`.

```json
{
  "format": "did-webplus-test-vector/1",
  "did": "did:webplus:example.com%3A3000:tv:demo:uHiB...",
  "name": "non-root-valid-from-not-increasing",
  "category": "conformance",
  "description": "...",
  "specRef": ["#validation-of-did-documents"],
  "didDocumentCount": 3,
  "expected": {
    "validDidDocumentCount": 2,
    "valid": false,
    "errorCode": "valid-from-not-strictly-increasing",
    "errorVersionId": 2
  },
  "keyTypes": ["Ed25519"],
  "hashFunctions": ["BLAKE3"],
  "generator": {
    "name": "did-webplus-test-vector",
    "version": "0.1.0",
    "seed": "did-webplus-test-vector-v1"
  }
}
```

| Field | Meaning |
|-------|---------|
| `format` | Schema / format version |
| `did` | DID for this vector (for `resolution`, the **resolution** DID / served path identity; the JSONL body may use a different DID) |
| `name` | Catalog (or fuzz-lite) name |
| `category` | `conformance`, `coverage-matrix`, `jsonl-structural`, `resolution`, `stress`, or `fuzz-lite` |
| `description` | Human-readable summary |
| `specRef` | Spec section references |
| `didDocumentCount` | Number of DID-document lines in the JSONL |
| `expected.validDidDocumentCount` | Leading docs that must validate (**normative** for non-`resolution`; for `resolution` see Expectation semantics) |
| `expected.valid` | `true` iff `validDidDocumentCount == didDocumentCount` |
| `expected.errorCode` | Advisory failure taxonomy (omitted when fully valid) |
| `expected.errorVersionId` | `versionId` of the first failing document (omitted when fully valid) |
| `keyTypes` / `hashFunctions` | Key/hash choices recorded from generation params |
| `generator.seed` | Original CLI `--seed` string (not the hex form in fuzz-lite names) |

## Expectation semantics

**Normative:** `expected.validDidDocumentCount` and `expected.valid` (except `resolution` — see below).

For non-`resolution` vectors (incremental ingest of the JSONL):

- Fully valid history → `validDidDocumentCount == didDocumentCount`, `valid: true`
- Root invalid → `validDidDocumentCount == 0`
- Valid prefix then failure → accept the first `validDidDocumentCount` documents; reject the next (if any)

For **`resolution`** vectors: the JSONL is a fully valid microledger, but `did` is a mismatched resolution / served-path identity. Metadata still has `validDidDocumentCount: 0` and `valid: false` — that means “reject relative to `did`,” **not** “JSONL fails at document 0.” Body-only checks must accept the whole file; identity checks / `resolve(did)` must fail.

**Advisory:** `errorCode` and `errorVersionId`. Other implementations need not match codes; the accept/reject outcomes above define conformance.

## Error-code taxonomy

Stable kebab-case strings (`ErrorCode` in the library). Codes mirror validation steps; they are metadata for harnesses and docs, not a normative error API.

| Code | Meaning |
|------|---------|
| `not-jcs-canonical` | Line is not JCS-canonical JSON |
| `valid-from-precision-exceeded` | `validFrom` exceeds allowed temporal precision |
| `valid-from-pre-epoch` | `validFrom` is before the Unix epoch |
| `valid-from-invalid-format` | `validFrom` not uppercase-`T`/`Z` RFC 3339 form |
| `vm-id-missing-query-params` | Verification-method `id` missing required query params |
| `vm-id-query-param-order` | Verification-method `id` query params in wrong order |
| `vm-id-selfhash-mismatch` | Verification-method `id` `selfHash` param mismatch |
| `vm-id-version-id-mismatch` | Verification-method `id` `versionId` param mismatch |
| `vm-id-missing-fragment` | Verification-method `id` missing fragment |
| `vm-id-controller-mismatch` | Verification-method `id` controller (DID prefix) does not match the document `id` |
| `vm-missing-kid` | Verification-method `publicKeyJwk` is missing required `kid` |
| `dangling-purpose-ref` | A purpose array references a verification-method fragment that does not exist |
| `self-hash-mismatch` | Document `selfHash` does not match computed self-hash |
| `self-hash-slot-mismatch` | Self-hash-bearing fields inconsistent |
| `invalid-proof-signature` | Proof JWS signature invalid |
| `malformed-proof-kid` | Proof JWS `kid` header is malformed (e.g. non-multicodec) |
| `update-rules-not-satisfied` | Proofs do not satisfy `updateRules` |
| `update-after-deactivation` | Update after DID deactivation (tombstone) |
| `root-version-id-nonzero` | Root has `versionId != 0` |
| `root-prev-did-document-self-hash-present` | Root unexpectedly includes `prevDIDDocumentSelfHash` |
| `non-root-id-mismatch` | Non-root `id` does not match expected DID |
| `prev-did-document-self-hash-mismatch` | Wrong `prevDIDDocumentSelfHash` |
| `valid-from-not-strictly-increasing` | Non-root `validFrom` not strictly greater |
| `version-id-not-incremented` | Non-root `versionId` not exactly previous + 1 |
| `malformed-jsonl-line` | JSONL line not valid JSON / otherwise malformed |
| `missing-required-field` | Required DID-document field missing |
| `malformed-version-id` | `versionId` invalid type or shape |
| `malformed-id` | DID document `id` malformed |
| `resolution-root-self-hash-mismatch` | Resolution URL root self-hash ≠ DID inside JSONL (body may still be valid) |
| `resolution-path-mismatch` | Resolution URL path ≠ DID path inside JSONL (host + root self-hash match) |
| `resolution-host-mismatch` | Resolution / VDR host ≠ DID host inside JSONL (path + root self-hash match) |
| `resolution-port-mismatch` | Resolution / VDR port ≠ DID port inside JSONL (content DID always has a port; host + path + root self-hash match) |

## Determinism notes

- Default seed: `did-webplus-test-vector-v1` (stable published DIDs when using defaults).
- Catalog vectors: per-vector RNG from `BLAKE3(global_seed || vector_name)`.
- Fuzz-lite: names `fuzz-lite-<seed_hex>-{index:05}` (`seed_hex` = full lowercase hex of the CLI seed UTF-8); RNG from the final name only (`BLAKE3(name)`), so the seed is not double-hashed. Original seed string remains in `generator.seed`.
- Timestamps start from a fixed base (`2025-01-01T00:00:00Z`) with deterministic increments.
- Re-running `generate` with the same seed and params yields the same DIDs and file contents for the same vector names.

## V2 specification sketch (deferred)

V1 materializes vectors to disk. A future V2 service would generate and stream them on demand, reusing `did-webplus-test-vector-lib`.

### Shape

- Axum service (mirroring `vdr-lib` layout) serving paths such as:

  `GET /{path...}/{root-self-hash}/did-documents.jsonl`

- Vector identity encoded in DID path components, e.g.
  `/tv/<vector-name>/<params>/<derived-root-self-hash>/...`
- Generation keyed entirely by `(seed, name, params)` — the same determinism V1 already provides — so any DID can be regenerated without storage.
- Procedural `test-vector.json` and `index.json`.
- Streaming JSONL (documents produced incrementally) and HTTP `Range` support so unbounded / DoS-stress version counts need not be fully materialized.

### Open items

- How the root self-hash is discovered before the client names it (likely an index endpoint mapping name → DID).
- Rate-limiting and size caps for the service itself.
- Encoding of size parameters for stress vectors in the path vs query string.

## Related crates

- [`did-webplus-test-vector-lib`](../test-vector-lib) — generation, catalogs, writer, metadata types; **authoritative design docs**
- [`did-webplus-core`](../core) — DID document APIs used by the builder
- [`did-webplus-doc-store`](../doc-store) — reference validation used in library self-check tests
