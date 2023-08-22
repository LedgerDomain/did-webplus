# did-webplus

Rust crate for prototype implementation of `did:webplus` DID method.

## Overview

The `did:web` DID method is simple and easy enough to implement using web2 technologies.  However, it is a rather weak DID method compared to others that incorporate more sophisticated cyptographic primitives and data structures (hashes, self-addressing identifiers, ledgers, formal DID document transactions, etc.).

The `did:webplus` DID method described and prototyped in this git repository is an effort to create an extension of `did:web` that provides stronger guarantees.  Note that there is no formal promise that `did:webplus` is actually directly compatible with `did:web`, just that `did:web` was the initial inspiration.

The idea is:
-   Each DID has an associated microledger of DID documents; each DID document references the hash of the previous DID document.  The microledger is intended to be immutable and append-only, and provides a totally-ordered sequence of DID documents whose validity durations are non-overlapping.
-   The first DID document in the microledger, called the root DID document, contains a Self-Addressing Identifier (SAID) which forms part of the DID itself, and therefore ties the DID to its root DID document, and prevents alterations to the root DID document.  The root DID document has its "versionId" field set to 0, and its "prevDIDDocumentHash" field is omitted to indicate that there is no previous DID document.  Currently the SAID uses the BLAKE3_256 hash function, rendered as `"E" + base64url_no_pad(hash(said_digest))`, as specified in the [SAID spec](https://www.ietf.org/archive/id/draft-ssmith-said-03.html).
-   Each DID document following the root DID document must obey strict constraints in order to provide the guarantees of the microledger.  In particular:
    -   The "prevDIDDocumentHash" field of DID document must be equal to the hash of the DID document immediately preceding it in the microledger.  Currently this is the BLAKE3-256 hash of the document, rendered as `"E" + base64url_no_pad(hash)` (this is the same formatting as specified in the [SAID spec](https://www.ietf.org/archive/id/draft-ssmith-said-03.html), for consistency and to allow for the rendered hash to specify which hash function is used).
    -   The "validFrom" field of a DID document must be later than that of the DID document immediately preceding it in the microledger.
    -   The "versionId" field of a DID document must be equal to 1 plus that of the DID document immediately preceding it in the microledger.
    -   Later development on the `did:webplus` DID method may add requirements about DID documents including signatures that prove the DID controller authored the update.
-   Signatures produced by the DID controller must include the following query params in the DID fragment which specifies the signing key.  The inclusion of these values makes commitments about the content of the microledger in data that is external to the `did:webplus` host, and therefore prevents certain modes of altering/forging DID document data.  See https://www.w3.org/TR/did-core/#did-parameters for a definition of the query params.
    -   `version_id`: specifies the `versionId` value of the most recent DID document.
    -   `version_time`: specifies the `validFrom` timestamp of the most recent DID document (though the DID spec makes it unclear if this can be any time within the validity duration of the DID document).
    -   `hl`: specifies the hash of the most recent DID document.  This provides verifiable content integrity.

## Example 1 -- Microledger

Root DID document:
```
{
  "id": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP",
  "validFrom": "2023-08-18T23:56:15.674525690Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP#key-1",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "controller": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP#key-1",
        "kty": "EC",
        "crv": "secp256k1",
        "x": "1pKM4zhV7FSGcfsrwDNA7pkYBxCEeLhxZuLLSedk2c0",
        "y": "3jvUoto-2AemhXVgXabEa7n97jKEmZu8RDiBXFPML4E"
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
  "id": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP",
  "prevDIDDocumentHash": "EPaPQSYlD7-Lb58Zc42gOyXwK4puxaRXW3jb-vVBPxzW",
  "validFrom": "2023-08-18T23:56:15.674958562Z",
  "versionId": 1,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP#key-1",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "controller": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP#key-1",
        "kty": "EC",
        "crv": "secp256k1",
        "x": "1pKM4zhV7FSGcfsrwDNA7pkYBxCEeLhxZuLLSedk2c0",
        "y": "3jvUoto-2AemhXVgXabEa7n97jKEmZu8RDiBXFPML4E"
      }
    },
    {
      "id": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP#key-2",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:webplus:example.com:EAHf6EEBKQ5KCMHs5mDkJTJFPXozUiUJKTsoyXTFyNRP",
      "publicKeyBase58": "WxbNdA24kW64p8eg7FMeW1hYYL72FYUcpPz5wDJ4s7N"
    }
  ],
  "authentication": [
    "#key-1"
  ],
  "assertionMethod": [
    "#key-2"
  ],
  "keyAgreement": [
    "#key-1"
  ],
  "capabilityInvocation": [
    "#key-2"
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
  "id": "did:webplus:example.com:EBsQFECtxdxNPtgGJn0mB1Mxrr70jlD7v1_HVnv_HFY8",
  "validFrom": "2023-08-22T07:07:12.711593231Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:EBsQFECtxdxNPtgGJn0mB1Mxrr70jlD7v1_HVnv_HFY8#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:EBsQFECtxdxNPtgGJn0mB1Mxrr70jlD7v1_HVnv_HFY8",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EBsQFECtxdxNPtgGJn0mB1Mxrr70jlD7v1_HVnv_HFY8#key-1",
        "kty": "EC",
        "crv": "secp256k1",
        "x": "-dAda8Qsqjn7LN5qsYK5pKo0Dao6JHP4mBh8Mylr5nQ",
        "y": "bPR-iXPx_IItdf_0hB3jyLWJJ5Ugi7eCODxYrJ4_6Mg"
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
eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6d2VicGx1czpleGFtcGxlLmNvbTpFQnNRRkVDdHhkeE5QdGdHSm4wbUIxTXhycjcwamxEN3YxX0hWbnZfSEZZOD92ZXJzaW9uSWQ9MCZobD1FTDRjOTRxUkFDSHNfVUZMRlZ2MzgwUXBuX2FJMGMwRXNIT3lTVnpZWFhLaCNrZXktMSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..QBenZBa3OAjBnkgbIMIlqkgWzui3egtUaGZOwUot7JpLjirOJ1FXGmVGS5BTni9IwoUJ9DNw6KTkthOLbWHR2w
```

The header of the above JWS is as follows.  Note that they key ID specified by the header commits to the versionId and hl (hash) of the DID document, so that the DID's microledger is anchored in two places -- the root DID document (by virtue of the SAID embedded in the DID itself) and this JWS (which is witnessed by some party and therefore is a commitment represented outside of the VDR for the DID).
```
{
  "alg": "ES256K",
  "kid": "did:webplus:example.com:EBsQFECtxdxNPtgGJn0mB1Mxrr70jlD7v1_HVnv_HFY8?versionId=0&hl=EL4c94qRACHs_UFLFVv380Qpn_aI0c0EsHOySVzYXXKh#key-1",
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
