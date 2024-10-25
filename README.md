# did-webplus

The `did:web` method makes straightforward use of familiar tools across a wide range of use cases. However, heavily regulated ecosystems such as the pharmaceutical supply chain demand additional guarantees of immutability and auditability, including seamless key rotation and a key usage history. `did:webplus` is a proposed fit-for-purpose DID method for use within the pharma supply chain credentialing community, with an eye towards releasing it into the wild for those communities that are similarly situated.

## Quick Overview

Component documentation:
-   [`did:webplus` Verifiable Data Registry (VDR) service](did-webplus-vdr/README.md)
-   [`did:webplus` Verifiable Data Gateway (VDG) service](did-webplus-vdg/README.md)
-   [`did-webplus` CLI tool](did-webplus-vdr/README.md)

Along with an overview and examples, this repository includes a Rust crate for prototype implementation of the `did:webplus` DID method. This repository provides initial reference implementations of the components described herein, and your feedback is welcome.

If you want to see concrete examples, skip to the Examples section.

To run the data model tests, which include printouts demonstrating various features and data structures, run

    cargo test --all-features -- --nocapture

The `--all-features` is necessary for now.

## Detailed Overview

The `did:web` DID method is simple and easy enough to implement using web2 technologies. However, compared to others that incorporate more sophisticated cryptographic primitives and data structures (hashes, self-addressing identifiers, ledgers, formal DID document transactions, etc.), `did:web` often falls short. One of the biggest challenges in delivering `did:web` within a highly regulated industry such as the pharma supply chain is its lack of built-in "historicity." Many real-world `did:web` implementations assume that W3C Verifiable Presentations are ephemeral, needing to be verified at time of receipt (e.g. to access a particular resource) but not requiring retroactive verifiability in the event of a later audit. Within the Drug Supply Chain Security Act (DSCSA) and similar contexts, where a VP's historical validity may need to be checked for years after its creation, permanence rather than ephemerality is the general rule.

The `did:webplus` DID method described and prototyped in this git repository is an effort to create a balanced, fit-for-purpose extension of `did:web` that provides stronger guarantees with a moderate implementation lift. (Note that there is no formal promise that `did:webplus` is actually directly compatible with `did:web`, just that `did:web` was the initial inspiration.)

## Data Model

Briefly, the idea is that each DID has an associated microledger of DID documents, with each DID document referencing the self-signature of the previous DID document.  The microledger is intended to be immutable, append-only, and allow updates only from authorized parties.  It provides a totally-ordered sequence of DID documents whose validity durations are non-overlapping. This is accomplished by the use of successive validFrom dates, as outlined in more detail below.
-   General structure and constraints on all DID documents
    -   Each DID document has an "id" field which defines the DID itself.
    -   Each DID document is self-signed-and-hashed, producing fields "selfSignature", "selfSignatureVerifier", and "selfHash".  The self-signing-and-hashing procedure is:
        -   Set all self-hash slots to the appropriate placeholder.
        -   Self-sign (this is explained [in the `selfsign` crate readme](https://github.com/LedgerDomain/selfsign)).This populates all self-signature and self-signature verifier slots.
        -   Self-hash (this is explained [in the `selfhash` crate readme](https://github.com/LedgerDomain/selfhash)).
    -   Each DID document has a "versionId" field, which starts at 0 upon DID creation and increases by 1 with each update.
    -   Each DID document has a "validFrom" field, defining the timestamp at which the DID document becomes current.
    -   The fragments defining the key IDs for each public key in the DID document are derived from the public keys themselves, using conventions found in KERI (a prefix indicating the key type, then the base64-encoding of the public key bytes).
-   The first DID document in the microledger, called the root DID document, contains a self-hash which forms part of the DID itself. This binds the DID to the content of its root DID document, and prevents alterations to the root DID document.
    -   The root DID document has its "versionId" field set to 0,
    -   The root DID document's "prevDIDDocumentSelfHash" field is omitted to indicate that there is no previous DID document.
    -   The root DID document's "selfSignatureVerifier" field must correspond to one of the public keys listed in the "capabilityInvocation" field of the root DID document itself.  This field defines which keys are authorized to update this DID's DID document, and in the case of the root DID document, it establishes an initial self-consistency for that authority.
-   Each DID document following the root DID document must obey strict constraints in order to provide the guarantees of the microledger.  In particular:
    -   The "prevDIDDocumentSelfHash" field of a DID document must be equal to the "selfHash" field of the DID document immediately preceding it in the microledger.
    -   The "validFrom" field of a DID document must be later than that of the DID document immediately preceding it in the microledger.
    -   The "versionId" field of a DID document must be equal to 1 plus that of the DID document immediately preceding it in the microledger.
    -   The DID document must be self-signed-and-hashed, though this self-signature and self-hash only involves the "selfSignature", "selfSignatureVerifier", and "selfHash" fields, and not the portions of the DID -- once the DID has been determined from the self-hash on the root DID document, it doesn't ever change.
    -   The "selfSignatureVerifier" field must correspond to one of the public keys listed in the previous DID document's "capabilityInvocation", since the previous DID document is what defines authorization to update the DID's DID document.

As outlined above, the validity duration applies to each DID document, and extends from the "validFrom" timestamp in the DID document until that DID document has been supplanted by the following DID document. If a DID document is the most recent, then its validity duration is extended through "now" and does not have a specified "validUntil" (expiration) timestamp. The validity duration is meant to assign to each timestamp a unique DID document from the sequence of DID documents for a DID, for the purposes of unambiguous historical DID document resolution.  The [DID document metadata](https://www.w3.org/TR/did-core/#did-document-metadata) returned as part of DID resolution helps in reasoning about this.

## Verifiable Data Registry (VDR)

Here are [instructions](did-webplus-vdr/README.md) on how to spin up the VDR service in a dockerized environment and run tests against it.

A Verifiable Data Registry in the context of `did:webplus` is a web host which hosts DID documents on behalf of DID controllers.  A DID controller determines the content of each DID document, producing a self-signature over each DID document to prove valid authorship, whereas the VDR verifies DID creation and DID updates and serves DID documents to clients performing DID resolution.  Thus a DID controller is the author of a DID, but the VDR is the origin of the DID's documents.

## Long-Term Non-Repudiability via Witnessing and Archival; Scope of Truth

Among the central goals of `did:webplus` is long-term non-repudiability, meaning that DID microledgers should be immutable and un-forkable, and should be resolvable for an indefinite amount of time.  Put differently, altering an existing DID document should be detectable and preventable, deleting a DID document should not be practically possible, and discontinuation of a Verifiable Data Registry (VDR) hosting a DID should not result in loss of the associated DID microledger.

By itself, a `did:webplus` VDR could delete DID documents, thereby violating the requirement for long-term non-repudiability and availability.  If the VDR colludes with a DID controller, a DID microledger could be altered by forking it at a certain point in its history.  This violates non-repudiability, immutability, and un-forkability of DID microledgers.  Thus a `did:webplus` VDR alone is not sufficient to guarantee the desired properties.

To this end, a couple of "witnessing" schemes are presented.  A parallel consideration is the "scope of truth" for the witnessed DID document updates, i.e. the breadth of agreement on which DID document updates are considered valid.

### Verifiable Data Gateway (VDG)

Here are [instructions](did-webplus-vdg/README.md) on how to spin up the VDG service in a dockerized environment and run tests against it.

A Verifiable Data Gateway is meant to be a realtime replica of potentially many VDRs.  A VDG retrieves, verifies, and stores all DID microledgers within some scope of interest.  This scope could be, for example, all VDRs operating within a certain industry subject to strict long-term audit regulations.  A VDG can also service DID resolution requests on behalf of users that choose to trust it.  A VDG serves several purposes:
-   A VDG is a long-term backup of all DID microledgers within the scope of interest, thereby meeting the need for long-term non-repudiability and resolvability.  A VDG is meant to be a highly available and robust service, and therefore be a bulwhark against VDR service outages.
-   A VDG acts as an external witness to DID creation and updates, verifying each operation, and can identify when an attempt is made to fork a DID.  In this case, some governance mechanism (which is out of the scope of this document) should be invoked to respond to the illegal DID operation.
-   A VDG tracks each DID microledger within the scope of interest and verifies updates to each DID microledger incrementally.  A user who chooses to trust a VDG can then achieve constant-time DID resolution by use of that VDG.  Furthermore, because the VDG handles verification of DID microledgers on behalf of the user, the user can employ a "light client" whose DID resolution process is basically identical to that of `did:web`, making for a form of backward compatibility with `did:web`.  The notable difference is the importance of the DID query parameters which must be used in signatures.

It is highly recommended that `did:webplus` be used with a VDG, so as to provide the strong guarantees outlined above.

Several different possible implementations have been proposed for a VDG, including:
-   A database-backed web service.
-   A git-based snapshot system.
-   An IPFS-backed service.  Note however that this would require using plain hashes for DID documents, instead of using self-hashes, as is currently done in `did:webplus`.

Related discussion:
-   https://github.com/LedgerDomain/did-webplus/issues/8

### Limited Witnessing via Signatures

Signatures produced by the DID controller (e.g. in JWS or when signing Verifiable Credentials) must include the following query params in the DID fragment which specifies the signing key.  The inclusion of the required query params acts as a limited witness to the DID document, i.e. it makes a commitment about the content of the current DID document in a place that is external to the `did:webplus` VDR.  In a limited way, this partially mitigates certain modes of altering/forging DID document data.  See https://www.w3.org/TR/did-core/#did-parameters for a definition of some of the query params.
-   `selfHash`: required - specifies the `selfHash` field value of the most current DID document as of signing.  This provides verifiable content integrity.
-   `versionId`: required - specifies the `versionId` field value of the current DID document as of signing.
-   `versionTime`: optional - specifies the timestamp at which this signature was generated.  The signing key must be present in the current DID document as of signing.  This query param is useful when the signed content does not itself contain the signature timestamp.  See https://www.w3.org/TR/xmlschema11-2/#dateTime regarding the format -- note in particular that it requires millisecond precision.

This form of witnessing binds the DID microledger at the time of signing in places external to both the VDR and the VDG, and therefore plays an important role in strengthening the `did:webplus` method.

### Scope of Truth for DID Documents

One consideration for DIDs is how broadly parties need to agree on which DID documents are valid.  The required "scope of truth" depends on the specific needs of the use case.  Here are three logical scopes of truth, but certainly more could be usefully defined.
-   Collaborator-scoped: VDRs each determine the state of truth for DIDs they host, analogous to how git repos are used in software development.
-   Consortium-scoped: A finite number of orgs use a single VDG to determine the state of truth for all DIDs in the scope of consortium.
-   Globally-scoped: Use a cluster of VDGs to determine the globally consistent state of truth for all DIDs.

## Locally Verified Cache for DID Resolvers

An agent using a DID resolver (e.g. a client that needs to verify signatures, credentials, presentations, etc) can retrieve, verify, and store their own replicas of relevant DID microledgers.  In this way they have their own private VDG, which acts as a "private" witness, and therefore can detect forked DIDs.  Furthermore, it has a local copy of DID microledgers against which it can do historical DID resolution fully offline.

Determining if a given DID document is the latest DID document, however, still requires querying the DID's VDR, and therefore can't be done offline.  This is needed if, for example, the DID controller needs to authenticate in realtime.

## Examples

-   [Creating and Updating a DID](doc/example-creating-and-updating-a-did.md)
-   [Signature Generation With Witness](doc/example-signature-generation-with-witness.md)

## Strengths/Weaknesses

-   **Strength:** The root DID document of a given DID can't be altered (i.e. it's computationally infeasible to alter), due to the use of the self-hash which forms a portion of the DID itself.  This commits the DID to the content of its root DID document.
-   **Weakness:** If a VDG is not used, it is possible for a DID to be forked (i.e. have two parallel "histories") which would violate the non-repudiation requirement.  However, this requires the VDR sysadmin and the DID controller to collude -- the DID controller to produce the forked DID document, the VDR to agree to replace the existing DID document with the forked one.  This is obviously easier if they're the same entity (e.g. the DID controller hosting their own VDR).  However, if the DID controller has produced any signatures that have been witnessed by others, then this could be detected (see below).
-   **Strength:** If one of the witnessing schemes is used (especially a VDG), then a forked DID microledger will be detected.  Governance actions can be taken against the offending DID and/or VDR.
-   **Weakness:** If a VDG is not used, it is possible for the VDR sysadmin to delete any number of DID documents, have a service outage, or even go offline permanently, thereby weakening non-repudiability.
-   **Strength:** Using a locally verified cache allows for historical DID resolution to happen offline, and therefore frequently used DIDs can resolve with very low latency.

## Comparison of classes of DID method.

`did:web` is a weak DID method.  `did:ethr` has been chosen to generally represent a "strong" DID method, though there are others that don't necessarily involve cryptocurrency.  `did:webplus` is meant to be a fit-for-purpose balance between strength and web2-oriented practicality, suited to meet the needs of regulated communities.

| Feature                                    | did:web | did:webplus without VDG | did:webplus with VDG | did:ethr |
|--------------------------------------------|---------|-------------------------|----------------------|----------|
| DID doc resolution is always available     | ❌      | ❌                      | ✔️                    | ✔️        |
| DID doc can't be deleted                   | ❌      | ❌                      | ✔️                    | ✔️        |
| Root DID doc can't be altered              | ❌      | ✔️                       | ✔️                    | ✔️        |
| Non-root DID doc can't be altered          | ❌      | ❌                      | ✔️                    | ✔️        |
| Has unambiguous update authorization rules | ❌      | ✔️                       | ✔️                    | ✔️        |
| Formal signature required to update        | ❌      | ✔️                       | ✔️                    | ✔️        |
| Guaranteed historical DID doc resolution   | ❌      | ❌                      | ✔️                    | ✔️        |
| Free of cryptocurrency                     | ✔️       | ✔️                       | ✔️                    | ❌       |
| Practical to self-host VDR                 | ✔️       | ✔️                       | ✔️                    | ❌       |
| Uses broadly adopted software technologies | ✔️       | ✔️                       | ✔️                    | ❌       |
| Fully decentralized                        | ✔️       | ✔️                       | ❌                   | ✔️        |

## References

-   [DID spec](https://www.w3.org/TR/did-core/)
-   [`selfhash` crate, which provides self-hashing capabilities](https://github.com/LedgerDomain/selfhash)
-   [`selfsign` crate, which provides self-signing capabilities](https://github.com/LedgerDomain/selfsign)

## License

[MIT](LICENSE)

## Final Thoughts

We're looking for feedback on this work-in-progress.  Please post in the issues section of this Github repository.
