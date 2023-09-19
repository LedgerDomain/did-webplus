# did-webplus

The `did:web` method makes straightforward use of familiar tools across a wide range of use cases. However, heavily regulated ecosystems such as the pharmaceutical supply chain demand additional guarantees of immutability and auditability, including seamless key rotation and a key usage history. `did:webplus` is a proposed fit-for-purpose DID method for use within the pharma supply chain credentialing community, with an eye towards releasing it into the wild for those communities that are similarly situated.

Along with an overview and examples, this repository includes a Rust crate for prototype implementation of the `did:webplus` DID method. This is a draft only, and your feedback is welcome.

If you want to see concrete examples, skip to the Examples section.

## Overview

The `did:web` DID method is simple and easy enough to implement using web2 technologies. However, compared to others that incorporate more sophisticated cryptographic primitives and data structures (hashes, self-addressing identifiers, ledgers, formal DID document transactions, etc.), `did:web` often falls short. One of the biggest challenges in delivering `did:web` within a highly regulated industry such as the pharma supply chain is its lack of built-in "historicity." Many real-world `did:web` implementations assume that W3C Verifiable Presentations are ephemeral, needing to be verified at time of receipt (e.g. to access a particular resource) but not requiring retroactive verifiability in the event of a later audit. Within the Drug Supply Chain Security Act (DSCSA) and similar contexts, where a VP's historical validity may need to be checked for years after its creation, permanence rather than ephemerality is the general rule.

The `did:webplus` DID method described and prototyped in this git repository is an effort to create a balanced, fit-for-purpose extension of `did:web` that provides stronger guarantees with a moderate implementation lift. (Note that there is no formal promise that `did:webplus` is actually directly compatible with `did:web`, just that `did:web` was the initial inspiration.)

Briefly, the idea is that each DID has an associated microledger of DID documents, with each DID document referencing the self-signature of the previous DID document.  The microledger is intended to be immutable, append-only, and allow updates only from authorized parties.  It provides a totally-ordered sequence of DID documents whose validity durations are non-overlapping. This is accomplished by the use of successive validFrom dates, as outlined in more detail below.
-   General structure and constraints on all DID documents
    -   Each DID document has an "id" field which defines the DID itself.
    -   Each DID document is self-signed, having fields "selfSignature" and "selfSignatureVerifier" which define the signature and the public key that verifies the self-signature.  The process for verifying a self-signature is explained [in the `selfsign` crate readme](https://github.com/LedgerDomain/selfsign).
    -   Each DID document has a "versionId" field, which starts at 0 upon DID creation and increases by 1 with each update.
    -   Each DID document has a "validFrom" field, defining the timestamp at which the DID document becomes current.
    -   The fragments defining the key IDs for each public key in the DID document are derived from the public keys themselves, using conventions found in KERI (a prefix indicating the key type, then the base64-encoding of the public key bytes).
-   The first DID document in the microledger, called the root DID document, contains a self-signature which forms part of the DID itself. This ties the DID to its root DID document, and prevents alterations to the root DID document.
    -   The root DID document has its "versionId" field set to 0,
    -   The root DID document's "prevDIDDocumentSelfSignature" field is omitted to indicate that there is no previous DID document.
    -   The self-signature on the root DID document includes all occurrences of the DID throughout the DID document.  This translates to having multiple "self-signature slots" as described [in the `selfsign` crate readme](https://github.com/LedgerDomain/selfsign).
    -   The root DID document's "selfSignatureVerifier" field must correspond to one of the public keys listed in the "capabilityInvocation" field of the root DID document itself.  This field defines which keys are authorized to update this DID's DID document, and in the case of the root DID document, it establishes an initial self-consistency for that authority.
-   Each DID document following the root DID document must obey strict constraints in order to provide the guarantees of the microledger.  In particular:
    -   The "prevDIDDocumentSelfSignature" field of a DID document must be equal to the "selfSignature" field of the DID document immediately preceding it in the microledger.
    -   The "validFrom" field of a DID document must be later than that of the DID document immediately preceding it in the microledger.
    -   The "versionId" field of a DID document must be equal to 1 plus that of the DID document immediately preceding it in the microledger.
    -   The DID document must be self-signed, though this self-signature only involves the "selfSignature" field, and not the portions of the DID (once the DID has been determined from the self-signature on the root DID document, it doesn't ever change).
    -   The "selfSignatureVerifier" field must correspond to one of the public keys listed in the previous DID document's "capabilityInvocation", since the previous DID document is what defines authorization to update the DID's DID document.
-   Signatures produced by the DID controller (e.g. in JWS or when signing Verifiable Credentials) must include the following query params in the DID fragment which specifies the signing key.  The inclusion of these values makes commitments about the content of the microledger in data that is external to the `did:webplus` host, and therefore prevents certain modes of altering/forging DID document data.  See https://www.w3.org/TR/did-core/#did-parameters for a definition of the query params.
    -   `versionId`: specifies the `versionId` value of the most recent DID document.
    -   `versionTime`: specifies the `validFrom` timestamp of the most recent DID document (though the DID spec makes it unclear if this can be any time within the validity duration of the DID document).
    -   `hl`: specifies the "selfSignature" field value of the most recent DID document.  This provides verifiable content integrity.

As outlined above, the validity duration applies to each DID document, and extends from the "validFrom" timestamp in the DID document until that DID document has been supplanted by the following DID document. If a DID document is the most recent, then its validity duration is extended through "now," and does not have a specified "validUntil" (expiration) timestamp. The validity duration is meant to assign to each timestamp a unique DID document from the sequence of DID documents for a DID, for the purposes of unambiguous historical DID document resolution.  The [DID document metadata](https://www.w3.org/TR/did-core/#did-document-metadata) returned as part of DID resolution helps in reasoning about this.

## Example 1 -- Microledger

Root DID document:
```
{
    "id": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
    "selfSignature": "0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
    "selfSignatureVerifier": "DvFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY",
    "validFrom": "2023-09-16T10:21:01.786453967Z",
    "versionId": 0,
    "verificationMethod": [
        {
            "id": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DvFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DvFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY",
                "kty": "OKP",
                "crv": "ed25519",
                "x": "vFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY"
            }
        },
        {
            "id": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs",
                "kty": "OKP",
                "crv": "ed25519",
                "x": "UjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs"
            }
        }
    ],
    "authentication": [
        "#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs"
    ],
    "assertionMethod": [
        "#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs"
    ],
    "keyAgreement": [
        "#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs"
    ],
    "capabilityInvocation": [
        "#DvFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY"
    ],
    "capabilityDelegation": [
        "#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs"
    ]
}
```

Next DID document:
```
{
    "id": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
    "selfSignature": "0BuaqoFcnaDd8inWxgpAo_Csf8XtrkiYtIuLFM909ltsuqknT4keMSUb-6rjz_OlRYFMfG5FBqLknTOUTb5LaYCA",
    "selfSignatureVerifier": "DvFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY",
    "prevDIDDocumentSelfSignature": "0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
    "validFrom": "2023-09-16T10:21:01.812269695Z",
    "versionId": 1,
    "verificationMethod": [
        {
            "id": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs",
                "kty": "OKP",
                "crv": "ed25519",
                "x": "UjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs"
            }
        },
        {
            "id": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DB2unMZjQsuLWQJ74QvXoi7UfRaRU4gNUrvlhLLZBoZ8",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DB2unMZjQsuLWQJ74QvXoi7UfRaRU4gNUrvlhLLZBoZ8",
                "kty": "OKP",
                "crv": "ed25519",
                "x": "B2unMZjQsuLWQJ74QvXoi7UfRaRU4gNUrvlhLLZBoZ8"
            }
        },
        {
            "id": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DvFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:0BYk_3ULiEHZWiNSbsfPlfVFRUmkVnUsMWNmYYr_ZH6E6iiXV3DV02eWIGOr8GvLSKKvSNzOEC_rLrVuDrbt7IDw#DvFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY",
                "kty": "OKP",
                "crv": "ed25519",
                "x": "vFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY"
            }
        }
    ],
    "authentication": [
        "#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs",
        "#DB2unMZjQsuLWQJ74QvXoi7UfRaRU4gNUrvlhLLZBoZ8"
    ],
    "assertionMethod": [
        "#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs"
    ],
    "keyAgreement": [
        "#DUjVX2eKAYGn0ytKNjB4acslBDZC05IGVcbsfkLU1GFs"
    ],
    "capabilityInvocation": [
        "#DvFxiJCFQO0mih6KURzVxlNlvtcav19a40u_dBp_Z-HY"
    ],
    "capabilityDelegation": [
        "#DB2unMZjQsuLWQJ74QvXoi7UfRaRU4gNUrvlhLLZBoZ8"
    ]
}
```

## Example 2 -- Signature committing to a particular DID document

Root DID document:
```
{
    "id": "did:webplus:example.com:0B2LYBZ06Bn0dq7ALo3kG5ie20sQKvv7yzmbA8KtKExC4PRiZ2io-hPxxOy-mQ2qb4yuGdAK0eKvipqcBlZSArDg",
    "selfSignature": "0B2LYBZ06Bn0dq7ALo3kG5ie20sQKvv7yzmbA8KtKExC4PRiZ2io-hPxxOy-mQ2qb4yuGdAK0eKvipqcBlZSArDg",
    "selfSignatureVerifier": "DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4",
    "validFrom": "2023-09-16T11:15:48.139470452Z",
    "versionId": 0,
    "verificationMethod": [
        {
            "id": "did:webplus:example.com:0B2LYBZ06Bn0dq7ALo3kG5ie20sQKvv7yzmbA8KtKExC4PRiZ2io-hPxxOy-mQ2qb4yuGdAK0eKvipqcBlZSArDg#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4",
            "type": "JsonWebKey2020",
            "controller": "did:webplus:example.com:0B2LYBZ06Bn0dq7ALo3kG5ie20sQKvv7yzmbA8KtKExC4PRiZ2io-hPxxOy-mQ2qb4yuGdAK0eKvipqcBlZSArDg",
            "publicKeyJwk": {
                "kid": "did:webplus:example.com:0B2LYBZ06Bn0dq7ALo3kG5ie20sQKvv7yzmbA8KtKExC4PRiZ2io-hPxxOy-mQ2qb4yuGdAK0eKvipqcBlZSArDg#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4",
                "kty": "OKP",
                "crv": "ed25519",
                "x": "tDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4"
            }
        }
    ],
    "authentication": [
        "#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4"
    ],
    "assertionMethod": [
        "#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4"
    ],
    "keyAgreement": [
        "#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4"
    ],
    "capabilityInvocation": [
        "#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4"
    ],
    "capabilityDelegation": [
        "#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4"
    ]
}
```

JWS (signature using `#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4` over message `"HIPPOS are much better than OSTRICHES"`):
```
eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmV4YW1wbGUuY29tOjBCMkxZQlowNkJuMGRxN0FMbzNrRzVpZTIwc1FLdnY3eXptYkE4S3RLRXhDNFBSaVoyaW8taFB4eE95LW1RMnFiNHl1R2RBSzBlS3ZpcHFjQmxaU0FyRGc_dmVyc2lvbklkPTAmaGw9MEIyTFlCWjA2Qm4wZHE3QUxvM2tHNWllMjBzUUt2djd5em1iQThLdEtFeEM0UFJpWjJpby1oUHh4T3ktbVEycWI0eXVHZEFLMGVLdmlwcWNCbFpTQXJEZyNEdER5RldCN1BENUxiS0tjQVlpbV9iV3ZUZldrbExTR2NSdzl1b20wUHBXNCIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..bWzUku77WvcUo0wP22kPBEAJmCOK4R5Vj45mMv_8p83PMav704QE-Et34VWQlaJeqi5KBFoGlJDcVtdt7M24CA
```

The header of the above JWS is as follows.  Note that the key ID specified by the header commits to the versionId and hl ("selfSignature" field value) of the DID document, so that the DID's microledger is anchored in two places: (1) the root DID document (by virtue of the self-signature embedded in the DID itself) and (2) the JWS below (which is witnessed by some party and therefore is a commitment represented outside of the VDR for the DID).
```
{
    "alg": "EdDSA",
    "kid": "did:webplus:example.com:0B2LYBZ06Bn0dq7ALo3kG5ie20sQKvv7yzmbA8KtKExC4PRiZ2io-hPxxOy-mQ2qb4yuGdAK0eKvipqcBlZSArDg?versionId=0&hl=0B2LYBZ06Bn0dq7ALo3kG5ie20sQKvv7yzmbA8KtKExC4PRiZ2io-hPxxOy-mQ2qb4yuGdAK0eKvipqcBlZSArDg#DtDyFWB7PD5LbKKcAYim_bWvTfWklLSGcRw9uom0PpW4",
    "crit": [
        "b64"
    ],
    "b64": false
}
```

## Strengths/Weaknesses

-   **Strength:** The root DID document of a given DID can't be altered (i.e. it's computationally infeasible to alter), due to the use of a self-signature to form a portion of the DID itself.
-   **Weakness:** It is possible for a non-root DID document to be altered, but it requires the VDR sysadmin and the DID controller to collude.  This is obviously easier if they're the same person.  However, if the DID controller has produced any signatures that have been witnessed by others, then this could be detected.
-   **Strength:** In principle it is possible to detect an illegally branched DID microledger (i.e. where the VDR sysadmin and the DID controller collude to alter or otherwise provide a fraudulent DID document) simply by witnessing two verified signatures from the same DID where the signature `kid` includes the same `versionId` query param value but different `hl` query param values.
-   **Weakness:** It is possible for the VDR sysadmin to delete any number of DID documents, thereby weakening non-repudiability.

Keeping a full mirror of the contents of a VDR would be an effective way to address the described weaknesses, but would require a "backup DID document resolution" step in the implementation of the DID method.  This is discussed a bit [here](https://github.com/LedgerDomain/did-webplus/issues/2#issuecomment-1709266483).  Ultimately, having a kind of mirroring-and-verifying gateway, which could pull potentially many `did:webplus` VDRs' content, would be a positive feature and would add robustness to the DID method.

## Comparison of classes of DID method.

`did:web` is a weak DID method.  `did:ethr` has been chosen to generally represent a "strong" DID method, though there are others that don't necessarily involve cryptocurrency.  `did:webplus` is meant to be a fit-for-purpose balance between strength and web2-oriented practicality, suited to meet the needs of regulated communities.

TODO: Add a non-cryptocurrency-based DID method to the table.

|                                            | did:web | did:webplus | did:ethr |
|--------------------------------------------|---------|-------------|----------|
| DID doc resolution is "always" available   | ❌      | ❌*        | ✔️       |
| VDR can't delete any existing DID doc      | ❌      | ❌         | ✔️       |
| VDR can't alter any existing DID doc       | ❌      | ✔️         | ✔️       |
| VDR won't allow collusion to branch a DID  | ❌      | ❌         | ✔️       |
| Has unambiguous update authorization rules | ❌      | ✔️         | ✔️       |
| Formal signature required to update        | ❌      | ✔️         | ✔️       |
| Historical DID doc resolution              | ❌      | ✔️         | ✔️       |
| Free of cryptocurrency                     | ✔️      | ✔️         | ❌       |
| Practical to self-host VDR                 | ✔️      | ✔️         | ❌       |

`*` If a mirror of a `did:webplus` VDR were kept, then it could serve to greatly increase service availability.

## References

-   [DID spec](https://www.w3.org/TR/did-core/)
-   [`selfsign` crate, which provides self-signing capabilities](https://github.com/LedgerDomain/selfsign)

## Final Thoughts and To-dos

-   Prototype a did:webplus resolver (via `ssi` crate) and incorporate that into this demo.

I'm looking for feedback on this work-in-progress.  Please email me at victor.dods@ledgerdomain.com with comments/questions.
