# did-webplus-test-vector

CLI and supporting library for generating a deterministic catalog of `did:webplus`
test-vector microledgers — either written to disk for static serving (`generate`)
or served in-memory over HTTP (`serve`).

Each vector has its own DID, JSONL microledger (`did-documents.jsonl`), and
machine-readable expectation metadata (`test-vector.json`). Harnesses discover
vectors via `index.json` (derived discovery; metadata remains authoritative).

Generation logic and full design docs live in [`did-webplus-test-vector-lib`](../test-vector-lib) (crate-level module docs in `src/lib.rs`). This crate is a thin clap binary over that library.

## Purpose

Produce reusable test vectors that exercise:

- **Conformance** — positive/negative pairs for DID-document validation rules (each negative breaks exactly one rule)
- **Coverage matrix** — key types × hash functions, both multibase bases, mixed-history and path variants
- **JSONL structural** — empty files, blank lines, CRLF, duplicate/trailing garbage lines, valid-prefix-then-invalid
- **Resolution** — valid microledgers whose resolution DID / served path disagrees with the DID inside `did-documents.jsonl` (host, port, path, or root self-hash)
- **Resolution scenario** — stateful multi-step resolution / DID-document-metadata / DID-resolution-metadata / local-only conformance (`resolution-scenario.json` beside a fully valid body)
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

Subcommands: `generate`, `rebuild-index`, and `serve`.

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

Always writes **all** categories: conformance, coverage-matrix, jsonl-structural, resolution, resolution-scenario, stress, and fuzz-lite (`--fuzz-lite-count 0` skips fuzz-lite). Progress goes to stderr. After writing, `index.json` under `--target-dir` is **rebuilt from every on-disk `test-vector.json`**. Pre-existing vectors with other names remain in the index. If a generated name already exists at a different DID path, the old vector directory is removed.

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

### `serve`

Eagerly generate the catalog into memory and serve the V1 URL layout over HTTP (axum; also [`spawn_test_vector_server`](../test-vector-lib) behind the lib `server` feature). Listen port = DID port (same as VDR). Size caps: `StressConfig` + `--fuzz-lite-count`. Streaming / non-materialized stress is deferred.

```bash
did-webplus-test-vector serve \
  --host localhost \
  --listen-port 3000 \
  --seed did-webplus-test-vector-v1
```

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--host <HOST>` | `DID_WEBPLUS_TEST_VECTOR_HOST` | `localhost` | DID hostname |
| `--listen-port <PORT>` | `DID_WEBPLUS_TEST_VECTOR_LISTEN_PORT` | `3000` | TCP listen port and DID port |
| `--did-path <p1:p2>` | `DID_WEBPLUS_TEST_VECTOR_DID_PATH` | *(none)* | Colon-separated DID path prefix in URLs |
| `--seed <STRING>` | `DID_WEBPLUS_TEST_VECTOR_SEED` | `did-webplus-test-vector-v1` | Global seed |
| `--fuzz-lite-count <N>` | `DID_WEBPLUS_TEST_VECTOR_FUZZ_LITE_COUNT` | `128` | Fuzz-lite count (`0` skips) |
| `--stress-versions <N,…>` | `DID_WEBPLUS_TEST_VECTOR_STRESS_VERSIONS` | *(catalog default)* | Override stress version-count tiers |

Endpoints:

- `GET /health`
- `GET /index.json`
- `GET /{path}/did-documents.jsonl` (Range: 206; 416 with `bytes */N` when up to date; body length follows the current per-vector serve-count, default all lines)
- `GET /{path}/test-vector.json`
- `GET /{path}/resolution-scenario.json` (resolution-scenario vectors only)
- Control (outside the DID resolution namespace):
  - `PUT /control/serve-count` — set how many leading jsonl lines a vector serves
  - `GET /control/request-count?path=...` — read jsonl GET count since last reset
  - `POST /control/reset` — reset all serve-counts to full and zero all request counters

Prefer `serve` for a live resolution origin (resolver tests and **resolution-scenario conformance**); prefer `generate` + a static file server for on-disk trees of the non-scenario categories. Black-box resolver harnesses: `resolve(did)` succeeds iff `expected.valid` / `groups.positive` (not line-by-line `validDidDocumentCount` — that is library self-check).

**Static-hosting caveat:** a published static catalog (e.g. the `did-webplus-spec/test-vector` submodule) may include `resolution-scenario.json` files for discovery and reading, but scenario *conformance* requires the live `serve` server — serve-count mutation and request counting are impossible on static hosting. Interop suites should run `did-webplus-test-vector serve` (e.g. a `Dockerfile.test-vector-server` container) alongside any static catalog server.

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
  - `resolution-scenario.json` — present only for the `resolution-scenario` category (ordered resolution steps + expected outcomes)
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
- `GET http://localhost:3000/<path>/resolution-scenario.json` serves the scenario artifact when present

`path` is the `path` field from `index.json` `vectors` (forward-slash path under `--target-dir`).

A `did:webplus` DID resolver against this catalog: **positive** vectors must resolve successfully; **negative** vectors (including `resolution`) must fail.

**Static hosting and resolution scenarios:** static Range-capable servers can host the generated tree, including `resolution-scenario.json` for discovery. Full scenario conformance (mutating how many documents the VDR serves mid-scenario, and asserting exact VDR request counts) requires the live `serve` command — see [Scenario harness requirements](#scenario-harness-requirements).

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
    "resolution-scenario": ["..."],
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

**`resolution-scenario` group:** these vectors are body-positive — their JSONL fully validates — so they also appear in `groups.positive`. Group membership under `resolution-scenario` distinguishes them for scenario runners. Plain black-box `resolve(did)`-latest harnesses may treat them as ordinary positive vectors; full scenario conformance requires the [scenario harness](#scenario-harness-requirements).

### Harness consumption

1. Fetch `index.json`.
2. Select a group (`positive`, `negative`, or a category).
3. Resolve each name via `vectors[name].path`.
4. Fetch JSONL + `test-vector.json` (and, for `resolution-scenario`, `resolution-scenario.json`).
5. Apply expectations (next section, or [Scenario expectation semantics](#scenario-expectation-semantics)). Treat error codes / error message text as advisory.

**Black-box resolver:** resolve `vectors[name].did` — expect success iff `expected.valid` (equivalently: name is in `groups.positive`).

**Incremental validator:** for non-`resolution` vectors, assert the accept/reject prefix from `expected.validDidDocumentCount` (see below). For `resolution`, the JSONL body must fully validate on its own, but binding it to `vectors[name].did` / the served path must fail (`document.id` must equal that DID).

**Resolution-scenario runner:** see [Scenario harness requirements](#scenario-harness-requirements). Do not rely on static hosting alone for conformance.

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
| `category` | `conformance`, `coverage-matrix`, `jsonl-structural`, `resolution`, `resolution-scenario`, `stress`, or `fuzz-lite` |
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

## `resolution-scenario.json` schema (v1)

Format string: `did-webplus-resolution-scenario/1`.

Written beside `did-documents.jsonl` / `test-vector.json` for vectors in the
`resolution-scenario` category. A conforming full resolver starts with an **empty**
DID document store and executes `steps` in order, retaining store state across steps.

```json
{
  "format": "did-webplus-resolution-scenario/1",
  "name": "cold-plain-did-no-metadata",
  "description": "Cold resolve of a plain DID with no metadata requested.",
  "specRef": ["#did-resolution-metadata"],
  "did": "did:webplus:example.com%3A3000:tv:demo:uHiB...",
  "steps": [
    {
      "servedDidDocumentCount": 3,
      "didQuery": "did:webplus:example.com%3A3000:tv:demo:uHiB...",
      "resolutionOptions": {
        "requestCreate": false,
        "requestNext": false,
        "requestLatest": false,
        "requestDeactivated": false,
        "localResolutionOnly": false
      },
      "expected": {
        "success": true,
        "didDocumentVersionId": 2,
        "didDocumentSelfHash": "uEiB...",
        "didDocumentMetadata": {},
        "didResolutionMetadata": {
          "contentType": "application/did+json",
          "fetchedUpdatesFromVDR": true,
          "didDocumentResolvedLocally": false,
          "didDocumentMetadataResolvedLocally": true
        },
        "vdrRequestCount": 1
      }
    },
    {
      "servedDidDocumentCount": 3,
      "didQuery": "did:webplus:example.com%3A3000:tv:demo:uHiB...?versionId=1",
      "resolutionOptions": {
        "requestCreate": true,
        "requestNext": false,
        "requestLatest": false,
        "requestDeactivated": false,
        "localResolutionOnly": false
      },
      "expected": {
        "success": true,
        "didDocumentVersionId": 1,
        "didDocumentSelfHash": "uEiB...",
        "didDocumentMetadata": {
          "created": "2025-01-01T00:00:00Z",
          "createdMilliseconds": "2025-01-01T00:00:00.001Z"
        },
        "didResolutionMetadata": {
          "contentType": "application/did+json",
          "fetchedUpdatesFromVDR": false,
          "didDocumentResolvedLocally": true,
          "didDocumentMetadataResolvedLocally": true
        },
        "vdrRequestCount": 0
      }
    }
  ]
}
```

On failure (`success: false`), omit `didDocumentVersionId` / `didDocumentSelfHash` /
`didDocumentMetadata`; `didResolutionMetadata.error` MUST be present (message advisory).

| Field | Meaning |
|-------|---------|
| `format` | Schema / format version (`did-webplus-resolution-scenario/1`) |
| `name` | Catalog name (matches the owning test vector) |
| `description` | Human-readable summary |
| `specRef` | Spec section references |
| `did` | DID identity of the owning microledger |
| `steps` | Ordered resolution steps (see below) |

### Step fields

| Field | Meaning |
|-------|---------|
| `servedDidDocumentCount` | How many leading `did-documents.jsonl` lines the VDR serves during this step; MUST be monotonically non-decreasing across steps |
| `didQuery` | DID URL to resolve (may include `selfHash` and/or `versionId` query params) |
| `resolutionOptions` | Wire-exact DID Resolution Options (see below) |
| `expected` | Expected outcome for a conforming full resolver |

### `resolutionOptions` (wire field names)

| Field | Meaning |
|-------|---------|
| `requestCreate` | Populate creation metadata (`created` / `createdMilliseconds`) |
| `requestNext` | Populate next-update metadata |
| `requestLatest` | Populate latest-update metadata |
| `requestDeactivated` | Populate `deactivated` |
| `localResolutionOnly` | If `true`, resolver MUST make zero network requests; fail with resolution metadata when needed data is not local |
| `accept` | Optional; ignored by did:webplus (document returned as stored JCS) |

### `expected` fields

| Field | Meaning |
|-------|---------|
| `success` | `true` if resolution must succeed; `false` if it must fail |
| `didDocumentVersionId` | Resolved document `versionId` (present iff `success`) |
| `didDocumentSelfHash` | Resolved document `selfHash` (present iff `success`) |
| `didDocumentMetadata` | Exact DID document metadata JSON, including `*Milliseconds` timestamp fields when requested (present iff `success`) |
| `didResolutionMetadata` | Exact resolution-metadata object; the three booleans are normative; on error, `error` present-only |
| `vdrRequestCount` | Exact HTTP GETs to this DID's `did-documents.jsonl` during the step (`0` = local-only / no VDR contact; `1` = single Range fetch) |

## Scenario expectation semantics

**Preconditions:**

1. Fresh empty DID document store **per scenario**.
2. Store persists across steps within a scenario.
3. Steps execute in the order listed in `steps`.
4. Before each step, the harness sets the VDR serve-count to `servedDidDocumentCount` and resets (or diffs) the jsonl request counter for that vector path.

**Normative (conformance):**

- Per-step `success` / failure
- On success: resolved document identity (`didDocumentVersionId`, `didDocumentSelfHash`)
- On success: byte-exact `didDocumentMetadata` values (including `created` / `createdMilliseconds`, `nextUpdate` / `nextUpdateMilliseconds` / `nextVersionId`, `updated` / `updatedMilliseconds` / `versionId`, `deactivated` as applicable). Whole-seconds fields MUST equal the floor of their `*Milliseconds` counterparts (`created` ← `createdMilliseconds`, etc.).
- Exact resolution-metadata booleans: `fetchedUpdatesFromVDR`, `didDocumentResolvedLocally`, `didDocumentMetadataResolvedLocally` (determined before any VDR fetch; `didDocumentMetadataResolvedLocally` is vacuously `true` when no metadata was requested)
- Exact `vdrRequestCount` (`0` proves local-only / locality; `1` proves single-range-fetch)
- On failure: `didResolutionMetadata.error` is present

**Advisory:**

- Error message / `error` string text need not match across implementations
- `contentType` is typically `"application/did+json"` but is not the primary conformance signal

Generation is deterministic (fixed timestamp base + whole-second increments; resolution scenarios add deterministic non-zero millisecond components to `validFrom`), so expected metadata timestamps are concrete literals, not relative placeholders.

## Scenario harness requirements

A conforming external scenario runner (e.g. interop suites consuming this catalog) needs:

1. **Resolver with per-step options and a persistent local store** across steps within a scenario (fresh empty store at scenario start). The Rust CLI `did-webplus-cli resolve` is the reference driver: it accepts `DIDResolutionOptionsArgs` (`--creation` / `-C`, `--next` / `-N`, `--latest` / `-L`, `--deactivated` / `-D`, `--local-resolution-only` / `-l`), doc-store path args, and emits JSON for the DID document plus both metadata objects.
2. **Live test-vector server** (`did-webplus-test-vector serve`) as the VDR / catalog origin — not static hosting alone.
3. **Control API** to truncate the served microledger and count jsonl GETs (see below).

### Control API examples

Paths are the `path` field from `index.json` (no leading `/`, no filename).

Set serve-count (serve the first `N` jsonl lines):

```bash
curl -sS -X PUT http://localhost:3000/control/serve-count \
  -H 'content-type: application/json' \
  -d '{"path":"uHiB...","servedDidDocumentCount":1}'
```

Example response:

```json
{
  "path": "uHiB...",
  "servedDidDocumentCount": 1,
  "servedOctetLength": 1234
}
```

Read request count (jsonl GETs since last reset):

```bash
curl -sS 'http://localhost:3000/control/request-count?path=uHiB...'
```

Example response:

```json
{
  "path": "uHiB...",
  "requestCount": 1
}
```

Reset all serve-counts to full and zero all request counters (`204 No Content`):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3000/control/reset
```

Per-step loop outline (matches the Rust resolver integration harness):

1. `POST /control/reset` (zeroes jsonl counters and restores full serve-count).
2. `PUT /control/serve-count` with this step's `servedDidDocumentCount`.
3. Resolve `didQuery` with `resolutionOptions` against the persistent store.
4. Assert normative fields of `expected`.
5. `GET /control/request-count?path=...` and assert equals `expected.vdrRequestCount`.

Fetch the scenario artifact via `GET /{path}/resolution-scenario.json`.

### Static-hosting caveat (interop)

The published static catalog (e.g. `did-webplus-spec/test-vector`, consumed by harnesses such as `poc-did-webplus-py/interop`) may ship `resolution-scenario.json` for discovery, but **scenario conformance requires the live `serve` server**. Serve-count mutation and request counting cannot work on a static Range server. Recommend adding a `did-webplus-test-vector serve` container (a `Dockerfile.test-vector-server` already exists in `poc-did-webplus-py`) alongside the static catalog server.

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
| `vm-kid-mismatch` | Verification-method `publicKeyJwk.kid` is present but does not match `id` |
| `vm-kid-not-fully-qualified` | Verification-method `publicKeyJwk.kid` is present but is not a fully-qualified DID URL |
| `dangling-purpose-ref` | A purpose array references a verification-method fragment that does not exist |
| `self-hash-mismatch` | Document `selfHash` does not match computed self-hash |
| `self-hash-slot-mismatch` | Self-hash-bearing fields inconsistent |
| `invalid-proof-signature` | Proof JWS signature invalid |
| `malformed-proof-kid` | Proof JWS `kid` header is malformed (e.g. non-multicodec) |
| `update-rules-not-satisfied` | Proofs do not satisfy `updateRules` |
| `update-after-deactivation` | Update after DID deactivation (tombstone) |
| `root-version-id-nonzero` | Root has `versionId != 0` |
| `root-prev-did-document-self-hash-present` | Root unexpectedly includes `prevDIDDocumentSelfHash` |
| `prev-did-document-self-hash-null` | `prevDIDDocumentSelfHash` is JSON `null` |
| `malformed-prev-did-document-self-hash` | `prevDIDDocumentSelfHash` is present but is not a valid MBHash |
| `non-root-prev-did-document-self-hash-missing` | Non-root omits required `prevDIDDocumentSelfHash` |
| `proofs-null` | `proofs` is JSON `null` |
| `malformed-proofs` | `proofs` is present but is not an array of strings |
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

## Related crates

- [`did-webplus-test-vector-lib`](../test-vector-lib) — generation, catalogs, writer, optional HTTP server, metadata types; **authoritative design docs**
- [`did-webplus-core`](../core) — DID document APIs used by the builder
- [`did-webplus-doc-store`](../doc-store) — reference validation used in library self-check tests
