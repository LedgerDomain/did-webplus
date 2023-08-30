# did-webplus

Rust crate for prototype implementation of `did:webplus` DID method.

## Overview

The `did:web` DID method is simple and easy enough to implement using web2 technologies.  However, it is a rather weak DID method compared to others that incorporate more sophisticated cyptographic primitives and data structures (hashes, self-addressing identifiers, ledgers, formal DID document transactions, etc.).

The `did:webplus` DID method described and prototyped in this git repository is an effort to create an extension of `did:web` that provides stronger guarantees.  Note that there is no formal promise that `did:webplus` is actually directly compatible with `did:web`, just that `did:web` was the initial inspiration.

The idea is:
-   Each DID has an associated microledger of DID documents; each DID document references the hash of the previous DID document.  The microledger is intended to be immutable and append-only, and provides a totally-ordered sequence of DID documents whose validity durations are non-overlapping.
-   The first DID document in the microledger, called the root DID document, contains a Self-Addressing Identifier (SAID) which forms part of the DID itself, and therefore ties the DID to its root DID document, and prevents alterations to the root DID document.  The root DID document has its "versionId" field set to 0, and its "prevDIDDocumentHash" field is omitted to indicate that there is no previous DID document.  The root DID document also has a "said" field which is set to the same SAID as in the DID, but in non-root DID documents, the "said" field is the only self-addressing part of the DID document.  Currently the SAID uses the BLAKE3_256 hash function, rendered as `"E" + base64url_no_pad(hash(said_digest))`, as specified in the [SAID spec](https://www.ietf.org/archive/id/draft-ssmith-said-03.html).
-   Each DID document following the root DID document must obey strict constraints in order to provide the guarantees of the microledger.  In particular:
    -   The "prevDIDDocumentSAID" field of DID document must be equal to the SAID field of the DID document immediately preceding it in the microledger.
    -   The "validFrom" field of a DID document must be later than that of the DID document immediately preceding it in the microledger.
    -   The "versionId" field of a DID document must be equal to 1 plus that of the DID document immediately preceding it in the microledger.
    -   Later development on the `did:webplus` DID method may add requirements about DID documents including signatures that prove the DID controller authored the update.
-   Signatures produced by the DID controller must include the following query params in the DID fragment which specifies the signing key.  The inclusion of these values makes commitments about the content of the microledger in data that is external to the `did:webplus` host, and therefore prevents certain modes of altering/forging DID document data.  See https://www.w3.org/TR/did-core/#did-parameters for a definition of the query params.
    -   `version_id`: specifies the `versionId` value of the most recent DID document.
    -   `version_time`: specifies the `validFrom` timestamp of the most recent DID document (though the DID spec makes it unclear if this can be any time within the validity duration of the DID document).
    -   `hl`: specifies the SAID field value of the most recent DID document.  This provides verifiable content integrity.

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

The header of the above JWS is as follows.  Note that they key ID specified by the header commits to the versionId and hl (SAID field value) of the DID document, so that the DID's microledger is anchored in two places -- the root DID document (by virtue of the SAID embedded in the DID itself) and this JWS (which is witnessed by some party and therefore is a commitment represented outside of the VDR for the DID).
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

-   Strength: The root DID document of a given DID can't be altered (i.e. it's computationally infeasible to alter), due to the use of a SAID to form a portion of the DID itself.
-   Weakness: It is possible for a non-root DID document to be altered, but it requires the VDR sysadmin and the DID controller to collude.  This is obviously easier if they're the same person.  However, if the DID controller has produced any signatures that have been witnessed by others, then this could be detected.
-   Strength: In principle it is possible to detect an illegally branched DID microledger (i.e. where the VDR sysadmin and the DID controller collude to alter or otherwise provide a fraudulent DID document) simply by witnessing two verified signatures from the same DID where the signature `kid` includes the same `versionId` query param value but different `hl` query param values.
-   Weakness: It is possible for the VDR sysadmin to delete any number of DID documents, thereby weakening non-repudiability.

Keeping a full mirror of the contents of a VDR would be an effective way to address the described weaknesses, but would require a "backup DID document resolution" step in the implementation of the DID method.  This might be a good feature in general,

## Comparison of classes of DID method.

`did:web` is a weak DID method.  `did:ethr` has been chosen to generally represent a "strong" DID method, though there are others that don't necessarily involve cryptocurrency.  `did:webplus` is meant to be balance between strength and web2-oriented practicality.

TODO: Add a non-cryptocurrency-based DID method to the table.

The criteria listed on the left are phrased such that "No" is bad, and "Yes" is good.

|                                            | did:web | did:webplus | did:ethr |
|--------------------------------------------|---------|-------------|----------|
| DID doc resolution is "always" available   | No      | No*         | Yes      |
| VDR can't delete any existing DID doc      | No      | No          | Yes      |
| VDR can't alter any existing DID doc       | No      | Yes         | Yes      |
| VDR won't allow collusion to branch a DID  | No      | No          | Yes      |
| Historical DID doc resolution              | No      | Yes         | Yes      |
| Free of cryptocurrency                     | Yes     | Yes         | No       |
| Practical to self-host VDR                 | Yes     | Yes         | No       |

`*` If a mirror of a `did:webplus` VDR were kept, then it could serve to greatly increase service availability.

## References

-   [DID spec](https://www.w3.org/TR/did-core/)
-   [Self-Addressing Identifiers](https://www.ietf.org/archive/id/draft-ssmith-said-03.html) (SAIDs)
-   [said crate](https://crates.io/crates/said) which provides an implementation of SAIDs

## To-dos

-   Prototype a did:webplus resolver (via `ssi`` crate) and incorporate that into this demo.
-   Require DID document updates to include a Self-Signed Identifier (SSID) (apparently this is called Self-Certifying Identifier (SCID); see https://github.com/WebOfTrust/keri/discussions/43) over the new DID document using a key listed in the previous DID document (need to figure out which key purpose is appropriate; it would be good to use one different than authentication or assertionMethod).  SSID is analogous to SAID except that instead of a hash, it produces a signature.  This requires defining SSIDs and writing an implementation of it.
