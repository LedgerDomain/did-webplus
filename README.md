# did-webplus

The `did:web` method makes straightforward use of familiar tools across a wide range of use cases. However, heavily regulated ecosystems such as the pharmaceutical supply chain demand additional guarantees of immutability and auditability, including seamless key rotation and a key usage history. `did:webplus` is a proposed fit-for-purpose DID method for use within the pharma supply chain credentialing community, with an eye towards releasing it into the wild for those communities that are similarly situated.

Along with an overview and examples, this repository includes a Rust crate for prototype implementation of the `did:webplus` DID method. This is a draft only, and your feedback is welcome.

## Overview

The `did:web` DID method is simple and easy enough to implement using web2 technologies. However, compared to others that incorporate more sophisticated cryptographic primitives and data structures (hashes, self-addressing identifiers, ledgers, formal DID document transactions, etc.), `did:web` often falls short. One of the biggest challenges in delivering `did:web` within a highly regulated industry such as the pharma supply chain is its lack of built-in "historicity." Many real-world `did:web` implementations assume that W3C Verifiable Presentations are ephemeral, needing to be verified at time of receipt (e.g. to access a particular resource) but not requiring retroactive verifiability in the event of a later audit. Within the Drug Supply Chain Security Act (DSCSA) and similar contexts, where a VP's historical validity may need to be checked for years after its creation, permanence rather than ephemerality is the general rule.

The `did:webplus` DID method described and prototyped in this git repository is an effort to create a balanced, fit-for-purpose extension of `did:web` that provides stronger guarantees with a moderate implementation lift. (Note that there is no formal promise that `did:webplus` is actually directly compatible with `did:web`, just that `did:web` was the initial inspiration.)

Briefly, the idea is that each DID has an associated microledger of DID documents, with each DID document referencing the Self-Addressing Identifier (SAID) of the previous DID document.  The microledger is intended to be immutable and append-only, and provides a totally-ordered sequence of DID documents whose validity durations are non-overlapping. This is accomplished by the use of successive validFrom dates, as outlined in more detail below.
-   The first DID document in the microledger, called the root DID document, contains a SAID which forms part of the DID itself. This ties the DID to its root DID document, and prevents alterations to the root DID document.  The root DID document has its "versionId" field set to 0, and its "prevDIDDocumentSAID" field is omitted to indicate that there is no previous DID document.  The root DID document also has a "said" field which is set to the same SAID as in the DID, but in non-root DID documents, the "said" field is the only self-addressing part of the DID document.  Currently the SAID uses the BLAKE3_256 hash function, rendered as `"E" + base64url_no_pad(hash(said_digest))`, as specified in the [SAID spec](https://www.ietf.org/archive/id/draft-ssmith-said-03.html).
-   Each DID document following the root DID document must obey strict constraints in order to provide the guarantees of the microledger.  In particular:
    -   The "prevDIDDocumentSAID" field of a DID document must be equal to the SAID field of the DID document immediately preceding it in the microledger.
    -   The "validFrom" field of a DID document must be later than that of the DID document immediately preceding it in the microledger.
    -   The "versionId" field of a DID document must be equal to 1 plus that of the DID document immediately preceding it in the microledger.
    -   Later development on the `did:webplus` DID method may add requirements about DID documents including signatures that prove the DID controller authored the update.
-   Signatures produced by the DID controller must include the following query params in the DID fragment which specifies the signing key.  The inclusion of these values makes commitments about the content of the microledger in data that is external to the `did:webplus` host, and therefore prevents certain modes of altering/forging DID document data.  See https://www.w3.org/TR/did-core/#did-parameters for a definition of the query params.
    -   `version_id`: specifies the `versionId` value of the most recent DID document.
    -   `version_time`: specifies the `validFrom` timestamp of the most recent DID document (though the DID spec makes it unclear if this can be any time within the validity duration of the DID document).
    -   `hl`: specifies the SAID field value of the most recent DID document.  This provides verifiable content integrity.

As outlined above, the validity duration applies to each DID document, and extends from the "validFrom" timestamp in the DID document until that DID document has been supplanted by the following DID document. If a DID document is the most recent, then its validity duration is extended through "now," and does not have a specified "validUntil" (expiration) timestamp. The validity duration is meant to assign to each timestamp a unique DID document from the sequence of DID documents for a DID, for the purposes of unambiguous historical DID document resolution.

## Example 1 -- Microledger

Root DID document:
```
{
    "id": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze",
    "said": "EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze",
    "validFrom": "2023-08-30T10:30:53.717406807Z",
    "versionId": 0,
    "verificationMethod": [
        {
            "id": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze#key-1",
                "kty": "EC",
                "crv": "secp256k1",
                "x": "0h4EEkloDOUJKW1WiDl-VLxQsEIaiKWCdZ9MzuiV59s",
                "y": "xzPBko1rZXAKfayRT1Os8mYctdsqP-ot7jTV_OEIuXw"
            }
        }
    ],
    "authentication": [
        "#key-1"
    ],
    "assertionMethod": [
        "#key-1"
    ],
    "keyAgreement": [
        "#key-1"
    ],
    "capabilityInvocation": [
        "#key-1"
    ],
    "capabilityDelegation": [
        "#key-1"
    ]
}
```

Next DID document:
```
{
    "id": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze",
    "said": "EFZ27Bip1XQMamfhO9kF045m-4Vcn3grQInzwzqN1hAR",
    "prevDIDDocumentSAID": "EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze",
    "validFrom": "2023-08-30T10:30:53.719012649Z",
    "versionId": 1,
    "verificationMethod": [
        {
            "id": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze#key-1",
                "kty": "EC",
                "crv": "secp256k1",
                "x": "0h4EEkloDOUJKW1WiDl-VLxQsEIaiKWCdZ9MzuiV59s",
                "y": "xzPBko1rZXAKfayRT1Os8mYctdsqP-ot7jTV_OEIuXw"
            }
        },
        {
            "id": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze#key-2",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:EN4mSHxoKO6Uq7NGr_Bx8UIluPIlg82XTQbYPH-7Ihze#key-2",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "92f5g_G6MIPh2J5eYZXeEbuGFjFi7PV88KNCfi5l9vo"
            }
        }
    ],
    "authentication": [
        "#key-1",
        "#key-2"
    ],
    "assertionMethod": [
        "#key-2"
    ],
    "keyAgreement": [
        "#key-1"
    ],
    "capabilityInvocation": [
        "#key-1"
    ],
    "capabilityDelegation": [
        "#key-1"
    ]
}
```

## Example 2 -- Signature committing to a particular DID document

Root DID document:
```
{
    "id": "did:webplus:example.com:EIqLYiI01qxNEZ8dRKdkDnXXqYUK0f-uxTHbChAe6kmU",
    "said": "EIqLYiI01qxNEZ8dRKdkDnXXqYUK0f-uxTHbChAe6kmU",
    "validFrom": "2023-08-30T10:33:54.895435859Z",
    "versionId": 0,
    "verificationMethod": [
        {
            "id": "did:webplus:example.com:EIqLYiI01qxNEZ8dRKdkDnXXqYUK0f-uxTHbChAe6kmU#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:EIqLYiI01qxNEZ8dRKdkDnXXqYUK0f-uxTHbChAe6kmU",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:EIqLYiI01qxNEZ8dRKdkDnXXqYUK0f-uxTHbChAe6kmU#key-1",
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "Qd829OrKoqvL1vGYQjR3NCDyPSJwAXdIy_a7qKI5WdQ"
            }
        }
    ],
    "authentication": [
        "#key-1"
    ],
    "assertionMethod": [
        "#key-1"
    ],
    "keyAgreement": [
        "#key-1"
    ],
    "capabilityInvocation": [
        "#key-1"
    ],
    "capabilityDelegation": [
        "#key-1"
    ]
}
```

JWS (signature using `#key-1` over message `"HIPPOS are much better than OSTRICHES"`):
```
eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmV4YW1wbGUuY29tOkVJcUxZaUkwMXF4TkVaOGRSS2RrRG5YWHFZVUswZi11eFRIYkNoQWU2a21VP3ZlcnNpb25JZD0wJmhsPUVJcUxZaUkwMXF4TkVaOGRSS2RrRG5YWHFZVUswZi11eFRIYkNoQWU2a21VI2tleS0xIiwiY3JpdCI6WyJiNjQiXSwiYjY0IjpmYWxzZX0..ZiZ9ZdwoKYh4rv3iJqM8OzX68c-ypiExfZ1CvkJRXjnDgpeEDHUJ0I3KhtqNxX5Mg9Dl3MaMV0zJFyknK-IsCg
```

The header of the above JWS is as follows.  Note that the key ID specified by the header commits to the versionId and hl (SAID field value) of the DID document, so that the DID's microledger is anchored in two places: (1) the root DID document (by virtue of the SAID embedded in the DID itself) and (2) the JWS below (which is witnessed by some party and therefore is a commitment represented outside of the VDR for the DID).
```
{
    "alg": "EdDSA",
    "kid": "did:webplus:example.com:EIqLYiI01qxNEZ8dRKdkDnXXqYUK0f-uxTHbChAe6kmU?versionId=0&hl=EIqLYiI01qxNEZ8dRKdkDnXXqYUK0f-uxTHbChAe6kmU#key-1",
    "crit": [
        "b64"
    ],
    "b64": false
}
```

## Strengths/Weaknesses

-   **Strength:** The root DID document of a given DID can't be altered (i.e. it's computationally infeasible to alter), due to the use of a SAID to form a portion of the DID itself.
-   **Weakness:** It is possible for a non-root DID document to be altered, but it requires the VDR sysadmin and the DID controller to collude.  This is obviously easier if they're the same person.  However, if the DID controller has produced any signatures that have been witnessed by others, then this could be detected.
-   **Strength:** In principle it is possible to detect an illegally branched DID microledger (i.e. where the VDR sysadmin and the DID controller collude to alter or otherwise provide a fraudulent DID document) simply by witnessing two verified signatures from the same DID where the signature `kid` includes the same `versionId` query param value but different `hl` query param values.
-   **Weakness:** It is possible for the VDR sysadmin to delete any number of DID documents, thereby weakening non-repudiability.

Keeping a full mirror of the contents of a VDR would be an effective way to address the described weaknesses, but would require a "backup DID document resolution" step in the implementation of the DID method.

## Comparison of classes of DID method.

`did:web` is a weak DID method.  `did:ethr` has been chosen to generally represent a "strong" DID method, though there are others that don't necessarily involve cryptocurrency.  `did:webplus` is meant to be a fit-for-purpose balance between strength and web2-oriented practicality, suited to meet the needs of regulated communities.

TODO: Add a non-cryptocurrency-based DID method to the table.

|                                            | did:web | did:webplus | did:ethr |
|--------------------------------------------|---------|-------------|----------|
| DID doc resolution is "always" available   | ❌      | ❌*        | ✔️       |
| VDR can't delete any existing DID doc      | ❌      | ❌         | ✔️       |
| VDR can't alter any existing DID doc       | ❌      | ✔️         | ✔️       |
| VDR won't allow collusion to branch a DID  | ❌      | ❌         | ✔️       |
| Historical DID doc resolution              | ❌      | ✔️         | ✔️       |
| Free of cryptocurrency                     | ✔️      | ✔️         | ❌       |
| Practical to self-host VDR                 | ✔️      | ✔️         | ❌       |

`*` If a mirror of a `did:webplus` VDR were kept, then it could serve to greatly increase service availability.

## References

-   [DID spec](https://www.w3.org/TR/did-core/)
-   [Self-Addressing Identifiers](https://www.ietf.org/archive/id/draft-ssmith-said-03.html) (SAIDs)
-   [said crate](https://crates.io/crates/said) which provides an implementation of SAIDs

## Final Thoughts and To-dos

-   Prototype a did:webplus resolver (via `ssi`` crate) and incorporate that into this demo.
-   Require DID document updates to be signed by an appropriate key in the previous DID document.  The [Capability Invocation](https://www.w3.org/TR/did-core/#capability-invocation) key purpose is intended for this use.
    -   Ideally this would be done using a Self-Certifying Identifier (SCID) (analogous to SAID except that instead of a hash over the document, a SCID is a signature over the document; see https://github.com/WebOfTrust/keri/discussions/43).  This would make it unambiguous that what is being signed is the DID document itself.  However, this requires defining SCIDs and writing an implementation of it.  This SCID would be used instead of the SAID to form the DID's microledger and as the hl field value in signatures using the DID.
    -   Another option would be to produce a JWS over the DID document, though this would be complicated by the fact that the JWS can't be embedded in the document in the same way a SCID could be.  There would need to be a specified deterministic procedure for producing the message-to-be-signed from the JWS-included DID document.  JSON is not particularly amenable to this, so this option is not ideal.  SCID (in analogy) to SAID, essentially already defines this procedure, and therefore would avoid this problem.

I'm looking for feedback on this work-in-progress.  Please email me at victor.dods@ledgerdomain.com with comments/questions.
