# To-dos

-   Restructure crate directories
    -   Put root crate (`did_webplus`) into a `core` subdir and maybe rename it to `did_webplus_core` (it's the core data model).
    -   Remove `did-webplus-` prefix from dirs, since it's redundant.
-   Maybe shorten `DIDDocStore`/`DIDDocStorage` names to simply `DocStore`/`DocStorage`.
-   Prototype a did:webplus resolver (via `ssi` crate) and incorporate that into this demo.
-   Consider making the `id` fields of the elements of `verificationMethod` also contain the appropriate query params (`versionId`, `selfHash`, and potentially even `validFrom`), so that the DID represents the exact value of the `kid` field that should go in the header for signatures using JWS and JWT, and it doesn't need to be separately tracked by the wallet.
-   In verified cache operations which store a "current as of" timestamp, need to figure out robust rules regarding comparing timestamps from different systems.  Make it clear that the "current as of" timestamp is a local timestamp, and that other timestamps are remote.  Perhaps make it clear that local and remote timestamps aren't necessarily directly comparable in the naive way.  Maybe the VDR should timestamp its responses so that the DID resolver can reason about local vs remote timestamps.  Yes, it should timestamp its responses, so that the DID document metadata can be correctly formed.
-   Add a "valid_until" timestamp to DID doc store rows and records, so that it's easy to determine validity duration and perform SQL queries on validity duration.
