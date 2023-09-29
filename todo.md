# To-dos

-   Prototype a did:webplus resolver (via `ssi` crate) and incorporate that into this demo.
-   Add pre-self-signature path components to `DIDWebplus` struct, so e.g. `did:webplus:example.com:identity:<self-signature>` is possible.
-   Consider making the `id` fields of the elements of `verificationMethod` also contain the appropriate query params (`versionId`, `selfHash`, and potentially even `validFrom`), so that the DID represents the exact value of the `kid` field that should go in the header for signatures using JWS and JWT, and it doesn't need to be separately tracked by the wallet.
