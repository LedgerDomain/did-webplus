# did-webplus-mock

The `did-webplus-mock` crate provides mock implementations[^1] which demonstrate the actual functioning of the various aspects of the `did:webplus` DID method.  There are a number of traits defined in the code which define APIs for the different components.  Note that this crate is a work in progress, and these APIs should not be considered stable yet.  The traits/APIs found here may or may not become an official part of the `did-webplus` crate.  The idea there would be to make creating implementations of `did:webplus` components as straightforward as possible.

[^1]: The mock implementations are meant to be a reference implementation -- completely functional, but they operate purely in-memory, and the client/server interaction simulated purely intra-process via function calls.  There is no persistent data store, and there is no HTTP client/server interaction.  They're suitable to be used in tests and to produce content for documentation (e.g. example DID microledgers, metadata, JWSes, etc).

## Traits/APIs

-   `Resolver` (client side of DID resolution)
    -   Fetch updates to DID microledgers for local caching and verification.
    -   Direct DID resolution; returns the requested DID document and associated metadata -- this should be nearly identical to `did:web` DID resolution.
-   `VDS` (server side of DID resolution) -- VDS = Verifiable Data Source (this is the property VDR and VDG have in common).
    -   Serve updates to DID microledgers.
    -   Serve a requested DID document and its associated metadata.
-   `VDRClient` (client side of DID create/update operations against VDR)
    -   Create DID; client supplies root DID document
    -   Update DID; client supplies new DID document
-   `MockVDR` (server side of VDR; this has not been factored into being a trait yet) -- VDR = Verifiable Data Registry.
    -   Create DID; verifies the supplied root DID document is valid, matches the host of the VDR, and meets any other criteria the VDR might impose.
    -   Update DID; verifies the supplied DID document is valid, is a valid update, and meets any other criteria the VDR might impose.

## Implementations of Traits/APIs

-   `MockResolverFull`
    -   Implements `Resolver`.
    -   Maintains its own local, verified cache of DID documents so that:
        -   It doesn't need to outsource verification to another service.
        -   It can do some forms of DID resolution fully offline once the relevant DID docs have been verified and cached.
-   `MockResolverThin`
    -   Implements `Resolver`.
    -   Outsources its verification and DID resolution to a VDG (which is an external web service).
-   `MockVDG` -- VDG = Verifiable Data Gateway
    -   Implements `VDS`
        -   Any DIDs that clients request are fetched by `MockVDG` are verified, locally cached, and then served to the requesting client.
    -   TODO: Implement pre-emptive fetching of DID documents from VDRs, or have VDRs push them to VDGs.
    -   Maintains its own local, verified cache of DID documents so that:
        -   "Thin" clients who trust the VDG don't have to do any verification themselves.
        -   Client requests can be serviced with as little runtime overhead as possible.
        -   There is a verified backup of DID microledgers for long-term repudiability.
-   `MockVDR`
    -   Implements `MockVDS`
    -   Provides methods for clients to create and update DIDs.
    -   Is the authority/origin on DIDs whose host components match that of the VDR.

## Additional Components

-   `MockVerifiedCache`
    -   Actually implements the fetching, verification, and caching of DID documents.
    -   Is used internally by `MockResolverFull` and `MockVDG`.
    -   Simulates a relational database backend for the DID document store.
-   `MockWallet`
    -   Provides an extremely minimal, NON-PRODUCTION digital wallet with capabilities:
        -   Create a DID
            -   Creates a set of private keys, one for each key purpose within the DID spec.
            -   Creates a DID document whose "verificationMethods" field represents the public keys corresponding to the created private keys.
            -   Interacts with the VDR (via `VDRClient`).
            -   Locally tracks the state of the controlled DID microledger.
        -   Update a DID
            -   Generates a new set of private keys to replace the existing set -- key rotation.  This mock implementation assumes there will only ever be a single key associated with each key purpose.
            -   Creates a DID document associated with those new keys (analogous to the "Create a DID" operation).
            -   Interacts with the VDR (via `VDRClient`).
            -   Locally tracks the (updated) state of the controlled DID microledger.
        -   For a controlled DID:
            -   Can provide a view into that DID's microledger.
            -   Can return the private (i.e. signing key) for a given key purpose (which is demonstrated in this crate's tests by signing a JWS).

