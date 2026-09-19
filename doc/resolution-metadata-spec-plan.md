# Spec edit plan: resolution metadata locality and scenarios

This document is a **concrete edit plan** for
[`../did-webplus-spec/spec.md`](../../did-webplus-spec/spec.md). It does **not**
apply those edits; landing them is a follow-up in the `did-webplus-spec` repo.

Authoritative behavior for every normative sentence below:

- Implementation: [`did-webplus/resolver/src/did_resolver_full.rs`](../did-webplus/resolver/src/did_resolver_full.rs)
- Pure model / draft normative wording:
  [`did-webplus/test-vector-lib/src/resolution_semantics.rs`](../did-webplus/test-vector-lib/src/resolution_semantics.rs)
  (module docs and `ResolutionSemantics`)
- Named scenario vectors:
  [`did-webplus/test-vector-lib/src/resolution_scenario_catalog.rs`](../did-webplus/test-vector-lib/src/resolution_scenario_catalog.rs)
- Harness-facing schema summary:
  [`did-webplus/test-vector/README.md`](../did-webplus/test-vector/README.md)
  (`resolution-scenario.json` schema v1)

Line numbers refer to `did-webplus-spec/spec.md` as of this plan and may drift;
prefer section headings / quoted phrases when applying edits.

---

## Sequencing (do this first)

**Land Part A (resolution-scenario test vectors) before editing the spec.**

Every normative sentence added by this plan MUST map to at least one published
scenario vector name. When drafting `spec.md`, cross-reference those names
inline (e.g. "see scenario `plain-did-always-fetches`"). Part A already
publishes the catalog; do not invent rules that no vector exercises.

Suggested cross-reference style in the spec:

> … MUST … ([resolution scenario](#conformance-resolution-scenarios)
> `plain-did-always-fetches`).

---

## Edit 1 — Replace the locality dodge with normative locality conditions

### Current text (anchor)

Under **DID Resolution Options** (~line 1404):

> For each field of the DID Document Metadata, there are conditions under which
> it can be produced purely from [locally-known data](#did-document-store), and
> an implementation SHOULD attempt to use only locally-known data whenever
> possible. **These conditions will not be specified in this document.**

### Action

Delete the sentence "These conditions will not be specified in this document."
Replace the surrounding paragraph with a new normative subsection (heading
suggestion: **Metadata locality conditions**), placed immediately before or
after the DID Resolution Options field list — preferably as its own sibling
under DID Resolution Mechanics / Full resolver behavior so that both Options
and Metadata can link to it.

### Proposed normative content (use oracle rules verbatim)

Introduce shared definitions used by the rest of the edits:

- **Locally-known data** for a DID is the contiguous verified prefix of that
  DID's microledger already archived in the resolver's
  [DID Document Store](#did-document-store) (versions `0 .. known_version_count-1`).
- Locality determinations below are made **before** any VDR fetch for the
  current resolution.
- A document (or "next" determination) is **locally satisfiable** when the
  corresponding rule below holds against locally-known data alone.

#### Needed documents

Given [DID Resolution Options](#did-resolution-options):

| Need | When |
|------|------|
| **Requested** DID document | Always |
| **Root** (version 0) | iff `requestCreate` |
| **Next** after the requested document | iff `requestNext` |
| **Latest** document | iff `requestLatest` **or** `requestDeactivated` |

#### Local satisfiability of the requested document

- A query-param-addressed document (`versionId` and/or `selfHash`) is locally
  satisfiable **iff** that document is present in the locally-known prefix.
  - Scenario vectors: `warm-version-id`, `warm-self-hash`, `warm-both-params`,
    `version-beyond-served`.
- Conflicting `versionId` and `selfHash` (both present, addressed version found
  locally, hashes disagree) is an error and MUST NOT trigger a VDR fetch.
  - Scenario: `conflicting-query-params`.
- **Plain-DID-requires-fetch rule:** a plain DID (no query params; "resolve
  latest") is **never** locally satisfiable unless the latest-known local
  document is **deactivated**. If it is deactivated, that document *is* the
  latest, there is no next, and the plain-DID request resolves to it without a
  fetch.
  - Active / non-deactivated warm store still fetches:
    `plain-did-always-fetches`, `cold-plain-did-no-metadata`.
  - Deactivated short-circuit: `deactivated-all-local`.

#### Local satisfiability of metadata groups

**Creation** (`requestCreate`):

- Locally satisfiable iff version 0 is present in the locally-known prefix.
- Scenarios: `request-creation-cold`, `request-creation-warm`.

**Next** (`requestNext`):

- Locally determined iff either:
  1. the next version after the requested document is present in the
     locally-known prefix, **or**
  2. deactivation implies there is no next (known absence): the requested
     document is deactivated, or the latest-known local document is deactivated
     and applies as above.
- If the requested document is present and is the latest-known local document
  but is **not** deactivated, "no next" is **not** locally known — a fetch is
  required to confirm absence or retrieve a successor.
- Scenarios: `request-next-with-local-next`, `request-next-at-latest`,
  `deactivated-all-local`.

**Latest** / **Deactivated** (`requestLatest` / `requestDeactivated`):

- Locally satisfiable iff the latest-known local document is deactivated (in
  which case it is known to be the true latest).
- Otherwise a fetch is required.
- Scenarios: `request-latest-forces-fetch`,
  `request-deactivated-forces-fetch`, `deactivated-all-local`.

#### Deactivation short-circuits (summarize explicitly)

When a locally-known document is deactivated (either as the query-addressed
requested document, or as the latest-known document for a plain DID):

1. That document is the latest.
2. There is no next document (`next` is known-absent).
3. Plain-DID resolution may complete locally.
4. All of creation / next / latest / deactivated metadata that depend only on
   that knowledge are locally satisfiable once the relevant documents are in
   store.

Scenario: `deactivated-all-local` (including with `localResolutionOnly: true`).

#### Soft efficiency guidance to harden

Keep (or strengthen) the existing SHOULD: an implementation MUST attempt to
satisfy needs from locally-known data first and MUST NOT fetch when every needed
document / determination is already locally satisfiable.

---

## Edit 2 — New normative subsection: Local-Only Resolution Mode

### Current text (anchor)

`localResolutionOnly` bullet under DID Resolution Options (~line 1414) is
informal ("some cases may not be resolvable… return an error").

### Action

1. Keep a short field definition in the Options list that points to the new
   subsection.
2. Add **Local-Only Resolution Mode** as a normative subsection (under Full DID
   Resolver requirements and/or DID Resolution Mechanics).

### Proposed normative content

When `localResolutionOnly` is `true`, a conforming Full DID Resolver:

1. MUST make **zero** network requests (including zero HTTP requests to the VDR
   or any VDG) for that resolution.
2. MUST succeed whenever every needed document / metadata determination (Edit 1)
   is locally satisfiable.
3. MUST fail with an error when any needed document / determination is not
   locally satisfiable.
4. On both success and failure, MUST still return
   [DID Resolution Metadata](#did-resolution-metadata) with the three
   `did:webplus`-specific booleans set from the **pre-fetch** determination
   (`fetchedUpdatesFromVDR` MUST be `false`).
5. All Full DID Resolver implementations MUST implement this mode.

Default when omitted: `false` (network requests allowed).

Scenarios: `local-only-matrix` (cold error; warm version-query success; warm
plain-DID error; warm `requestLatest` error), plus `deactivated-all-local`
(success under local-only when deactivated).

---

## Edit 3 — Tighten DID Resolution Metadata booleans

### Current text (anchor)

`did:webplus`-specific fields under **DID Resolution Metadata** (~lines
1422–1425). Wording today is descriptive and under-specifies vacuous metadata
and error responses.

### Action

Replace the three boolean bullets with normative definitions that match the
oracle / `DIDResolverFull` pre-fetch determination.

### Proposed normative content

The three booleans are determined **before** any VDR fetch for the current
resolution. Their values MUST NOT be revised after a fetch (they describe the
pre-fetch locality determination, not post-fetch completeness).

- **`didDocumentResolvedLocally`**: `true` iff the requested DID document was
  already present in locally-known data before any fetch; otherwise `false`.
  - Can be `true` while `fetchedUpdatesFromVDR` is also `true` when the
    document was local but requested metadata forced a fetch
    (e.g. `request-next-at-latest`, `request-latest-forces-fetch`).

- **`didDocumentMetadataResolvedLocally`**: `true` iff every *requested*
  metadata group (creation / next / latest-or-deactivated) was locally
  satisfiable before any fetch; otherwise `false`.
  - **Vacuous true:** when no metadata is requested
    (`requestCreate`, `requestNext`, `requestLatest`, and `requestDeactivated`
    are all false), this MUST be `true`.
    Scenario: `cold-plain-did-no-metadata`.

- **`fetchedUpdatesFromVDR`**: `true` iff this resolution performed a VDR fetch
  (see Edit 4); otherwise `false`. Even a fetch that returns zero new bytes
  counts as `true`.

**Error responses:** whenever resolution fails, the resolver MUST still return
DID Resolution Metadata including these three booleans (and MAY include
`error`). Error message text is advisory for conformance; boolean values and
presence of `error` are normative.
Scenarios: `local-only-matrix`, `conflicting-query-params`,
`version-beyond-served`.

---

## Edit 4 — Tighten fetch efficiency (at most one Range GET)

### Current text (anchors)

- VDR MUST support range-based HTTP GET (~line 263) — already REQUIRED; keep.
- Full DID Resolver MUST use HTTP Range-Based GET for the unfetched portion
  (~lines 356–357) — keep the octet-offset rule; tighten cardinality.

### Action

Add an explicit cardinality / efficiency requirement to the Full DID Resolver
MUST list (near ~356):

### Proposed normative content

- A single DID resolution MUST perform **at most one** VDR fetch of that DID's
  `did-documents.jsonl`.
- When a fetch is performed, it MUST be an HTTP Range GET whose start octet is
  the locally-known offset (byte 0 if nothing is archived; otherwise immediately
  after the JCS serialization of the last archived DID document — existing
  trailing-newline rule at ~357 remains).
- VDR HTTP Range support remains REQUIRED (already stated); resolvers rely on
  it for this efficiency property.
- After a successful fetch+validate, locally-known data expands to include the
  newly archived documents (scenario `incremental-range-fetch` asserts exactly
  one request per step and correct continuation).

Scenario vectors: `incremental-range-fetch` (`vdrRequestCount: 1` per fetching
step), all fetch scenarios assert `vdrRequestCount` is `0` or `1` never
greater.

---

## Edit 5 — Fix inaccurate "not the latest" rule (~line 269)

### Current text (anchor)

Under **DID Resolve**, second bullet (~line 269):

> If the requested DID document is already present in the DID Resolver's
> [DID Document Store](#did-document-store) **and is not the latest DID document
> present in that** [DID Document Store](#did-document-store), then it can be
> returned without contacting the VDR. Otherwise, updates must be fetched…

### Problem

The actual rule is **presence** of the requested document (for query-param
addressing), not "non-latestness." A present non-latest document can still be
returned without a VDR contact when no metadata forces a fetch. Conversely,
metadata requests (`requestNext` at the local tip, `requestLatest`,
`requestDeactivated`) are what force fetches even when the requested document
is already local. Plain DID resolution always fetches unless the
deactivation short-circuit applies (Edit 1).

### Action

Replace that sentence with wording aligned to Edit 1, for example:

> If the requested DID document is addressed by `selfHash` and/or `versionId`
> and is already present in the DID Resolver's DID Document Store, and every
> requested metadata group is locally satisfiable per
> [Metadata locality conditions](#metadata-locality-conditions), then the
> resolver MUST return that document without contacting the VDR. Otherwise the
> resolver MUST fetch updates from the VDR (subject to
> `localResolutionOnly`) in order to retrieve missing documents and/or complete
> metadata. Resolving a plain DID (no query parameters) always requires a VDR
> fetch unless the latest-known local document is deactivated.

Also repair the truncated first bullet at ~268 ("The query" appears cut off)
while touching this section, if still incomplete when applying the edit.

Cross-refs: `warm-version-id` / `warm-self-hash` / `warm-both-params` (no
fetch); `plain-did-always-fetches`; `request-latest-forces-fetch`;
`request-next-at-latest`.

---

## Edit 6 — Add Conformance: resolution scenarios

### Action

Add a new section (suggested heading: **Conformance: resolution scenarios**;
anchor `#conformance-resolution-scenarios`), likely near other conformance /
test-vector discussion or under DID Resolution Mechanics. The section
normatively requires Full DID Resolver implementations to pass the published
scenario vectors.

### Proposed normative content

#### Schema

Published vectors use format string `did-webplus-resolution-scenario/1`
(`resolution-scenario.json` beside `did-documents.jsonl` / `test-vector.json`).
Document the schema at a summary level (or normative reference to the catalog
README), including:

- Top-level: `format`, `name`, `description`, `specRef`, `did`, `steps`
- Per step: `servedDidDocumentCount`, `didQuery`, `resolutionOptions`,
  `expected`
- `resolutionOptions` wire names: `requestCreate`, `requestNext`,
  `requestLatest`, `requestDeactivated`, `localResolutionOnly`
- `expected`: `success`; on success exact `didDocumentVersionId`,
  `didDocumentSelfHash`, exact `didDocumentMetadata`; always exact
  `didResolutionMetadata` booleans; exact `vdrRequestCount`

Point readers to the living field table in
`did-webplus/test-vector/README.md` and to the generated catalog under
`did-webplus-spec/test-vector/` once published.

Resolution-scenario microledgers use fractional-second `validFrom` timestamps
(deterministic non-zero millisecond components; whole-seconds floors advance by
one second per version so timestamps stay strictly increasing). Expected
`didDocumentMetadata` therefore includes both the required `*Milliseconds`
fields and their DID-core whole-seconds counterparts, with the relationship:

- `created` = floor-to-seconds(`createdMilliseconds`)
- `updated` = floor-to-seconds(`updatedMilliseconds`)
- `nextUpdate` = floor-to-seconds(`nextUpdateMilliseconds`)

Harnesses MUST compare metadata byte-exactly; that comparison is what locks the
truncation relationship.

#### Preconditions and harness

A conforming run of a scenario:

1. Starts with a **fresh empty** DID Document Store.
2. Executes `steps` **in order**, retaining store state across steps within the
   scenario.
3. Before each step, sets the VDR to serve exactly the leading
   `servedDidDocumentCount` documents of that vector's `did-documents.jsonl`.
4. Counts HTTP GET requests to that DID's `did-documents.jsonl` during the step
   (`vdrRequestCount`).
5. Invokes the resolver with the step's `didQuery` and `resolutionOptions`.

Harness control surface (live test-vector server; not available on static
hosting alone):

- `PUT /control/serve-count`
- `GET /control/request-count?path=...`
- `POST /control/reset`

Static catalogs MAY ship `resolution-scenario.json` for discovery; scenario
**conformance** requires a Range-capable origin that supports serve-count
mutation and request counting (the `did-webplus-test-vector serve` command).

#### Normative vs advisory expectations

| Normative | Advisory |
|-----------|----------|
| Per-step success / failure | Error message string text |
| Resolved document identity (`versionId` / `selfHash`) | — |
| Exact `didDocumentMetadata` values (including `*Milliseconds` fields) | — |
| Whole-seconds counterparts (`created` / `updated` / `nextUpdate`) equal the floor of the corresponding `*Milliseconds` timestamps | — |
| Exact resolution-metadata booleans; `error` present-only on failure | — |
| Exact `vdrRequestCount` (`0` = no VDR contact; `1` = single Range fetch) | — |

#### Conformance requirement

All Full DID Resolver implementations MUST pass all published
`resolution-scenario` vectors in the official catalog (exact metadata and
boolean values normative as above).

Named scenarios to list or link from normative prose elsewhere (Edit 1–5):

| Name | Role |
|------|------|
| `cold-plain-did-no-metadata` | Cold plain DID; vacuous metadata locality |
| `warm-version-id` | Local query by versionId |
| `warm-self-hash` | Local query by selfHash |
| `warm-both-params` | Agreeing query params |
| `conflicting-query-params` | Conflict error, no fetch |
| `plain-did-always-fetches` | Plain DID fetch even when warm |
| `request-creation-cold` / `request-creation-warm` | Creation metadata locality |
| `request-next-with-local-next` | Next present locally |
| `request-next-at-latest` | Next absence needs fetch |
| `request-latest-forces-fetch` | Latest metadata forces fetch |
| `request-deactivated-forces-fetch` | Deactivated metadata forces fetch |
| `deactivated-all-local` | Deactivation short-circuit + local-only success |
| `local-only-matrix` | Local-only success/failure matrix |
| `incremental-range-fetch` | Single Range continuation |
| `version-beyond-served` | Fetch then missing-version error |

---

## Edit application checklist (for the spec PR)

When opening the `did-webplus-spec` PR, apply in roughly this order:

1. Confirm Part A catalog is published / submodule updated so every name above
   resolves in the served tree.
2. Edit 5 (fix ~269) — stop teaching the wrong rule early in the doc.
3. Edit 1 (locality conditions) — foundational definitions.
4. Edit 2 (local-only mode).
5. Edit 3 (resolution metadata booleans).
6. Edit 4 (at-most-one Range GET) — fold into Full DID Resolver MUST list.
7. Edit 6 (conformance section) — then sprinkle scenario-name cross-refs into
   Edits 1–5.
8. Spec editorial pass: fix truncated "The query" at ~268 if still present;
   ensure anchors / ToC updated; do not weaken existing VDR Range REQUIREDs.

### Out of scope for that PR (also out of scope here)

- Thin resolver / VDG scenario conformance.
- Changing Rust implementation behavior (vectors + `DIDResolverFull` already
  define the target).
- Interop runner work in `poc-did-webplus-py` (enabled by Part A README docs).
