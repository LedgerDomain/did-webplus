# Example: Creating and Updating a DID

This example can be run via command:

    cargo test --all-features -- --nocapture test_example_creating_and_updating_a_did

## Creating a DID

For now, let's generate a single Ed25519 key to use in all the verification methods for the DID we will create.  In JWK format, the private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "m7AuUCD1LhpiPhAOvNZyvbpM75PgUhdQqFKLCkSiXT4",
  "d": "UmBDdU_9oHmb05riF8X-_bruTOvQHjUm5fNH_e_sV_s"
}
```

We'll also need a key that is authorized to update the DID document.  In publicKeyMultibase format, the public key is:

```
u7QFEfNa-IIxpxs1thps4nLKtOrXylS7ObhaSJzNmePsg2Q
```

Creating a DID produces the root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
  "selfHash": "uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
  "updateRules": {
    "key": "u7QFEfNa-IIxpxs1thps4nLKtOrXylS7ObhaSJzNmePsg2Q"
  },
  "validFrom": "2025-10-03T03:24:07.372913003Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "m7AuUCD1LhpiPhAOvNZyvbpM75PgUhdQqFKLCkSiXT4"
      }
    }
  ],
  "authentication": [
    "#0"
  ],
  "assertionMethod": [
    "#0"
  ],
  "keyAgreement": [
    "#0"
  ],
  "capabilityInvocation": [
    "#0"
  ],
  "capabilityDelegation": [
    "#0"
  ]
}
```

Note that the `updateRules` field is what defines update authorization for this DID document.

The associated DID document metadata (at the time of DID creation) is:

```json
{
  "created": "2025-10-03T03:24:07.372913003Z",
  "nextUpdate": null,
  "nextVersionId": null,
  "updated": "2025-10-03T03:24:07.372913003Z",
  "versionId": 0
}
```

We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:

```json
{
  "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg?selfHash=uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg&versionId=0#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "m7AuUCD1LhpiPhAOvNZyvbpM75PgUhdQqFKLCkSiXT4",
  "d": "UmBDdU_9oHmb05riF8X-_bruTOvQHjUm5fNH_e_sV_s"
}
```

## Updating the DID

Let's generate another key to rotate in for some verification methods.  In JWK format, the new private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "eyvv0Rmvr8SFkv0mSKGai_ZWQpSv5APmPY1s0OwQo9k",
  "d": "H0iD_50oSOukrGxHfjwYyoG-uLVTVvE1BMkg-lJbkuc"
}
```

A new update key is also needed.  In publicKeyMultibase format, the new public key is:

```
u7QGqH3MzfA4cTIaDEnmum-YXEaCnIvejDzVAnMP160tcbg
```

Updating a DID produces the next DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
  "selfHash": "uHiCGrkkj7tWJ5F00DHLmyLtJszjRFjSICIcQlbrAdGVNog",
  "prevDIDDocumentSelfHash": "uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
  "updateRules": {
    "key": "u7QGqH3MzfA4cTIaDEnmum-YXEaCnIvejDzVAnMP160tcbg"
  },
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRkVmTmEtSUl4cHhzMXRocHM0bkxLdE9yWHlsUzdPYmhhU0p6Tm1lUHNnMlEiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..2owPha5M5xR3PRjLUmIKXqRfBJoGYVeM4Hs835m54sifIrrl5bDogEmGfWX4ZL4dCE2aHQ0Y20qzZy0xEPcLDA"
  ],
  "validFrom": "2025-10-03T03:24:07.380981642Z",
  "versionId": 1,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "m7AuUCD1LhpiPhAOvNZyvbpM75PgUhdQqFKLCkSiXT4"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#1",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "eyvv0Rmvr8SFkv0mSKGai_ZWQpSv5APmPY1s0OwQo9k"
      }
    }
  ],
  "authentication": [
    "#0",
    "#1"
  ],
  "assertionMethod": [
    "#0"
  ],
  "keyAgreement": [
    "#0"
  ],
  "capabilityInvocation": [
    "#1"
  ],
  "capabilityDelegation": [
    "#0"
  ]
}
```

Note that the `proofs` field contains signatures (in JWS format) that are to be validated and used with the `updateRules` field of the previous DID document to verify update authorization.  Note that the JWS proof has a detached payload, and decodes as:

```json
{
  "header": {
    "alg": "Ed25519",
    "b64": false,
    "crit": [
      "b64"
    ],
    "kid": "u7QFEfNa-IIxpxs1thps4nLKtOrXylS7ObhaSJzNmePsg2Q"
  },
  "payload": null,
  "signature": "2owPha5M5xR3PRjLUmIKXqRfBJoGYVeM4Hs835m54sifIrrl5bDogEmGfWX4ZL4dCE2aHQ0Y20qzZy0xEPcLDA"
}
```

The associated DID document metadata (at the time of DID update) is:

```json
{
  "created": "2025-10-03T03:24:07.372913003Z",
  "nextUpdate": null,
  "nextVersionId": null,
  "updated": "2025-10-03T03:24:07.380981642Z",
  "versionId": 1
}
```

However, the DID document metadata associated with the root DID document has now become:

```json
{
  "created": "2025-10-03T03:24:07.372913003Z",
  "nextUpdate": "2025-10-03T03:24:07.380981642Z",
  "nextVersionId": 1,
  "updated": "2025-10-03T03:24:07.380981642Z",
  "versionId": 1
}
```

We set the `kid` field of each private JWK to point to the current DID document:

```json
{
  "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg?selfHash=uHiCGrkkj7tWJ5F00DHLmyLtJszjRFjSICIcQlbrAdGVNog&versionId=1#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "m7AuUCD1LhpiPhAOvNZyvbpM75PgUhdQqFKLCkSiXT4",
  "d": "UmBDdU_9oHmb05riF8X-_bruTOvQHjUm5fNH_e_sV_s"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg?selfHash=uHiCGrkkj7tWJ5F00DHLmyLtJszjRFjSICIcQlbrAdGVNog&versionId=1#1",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "eyvv0Rmvr8SFkv0mSKGai_ZWQpSv5APmPY1s0OwQo9k",
  "d": "H0iD_50oSOukrGxHfjwYyoG-uLVTVvE1BMkg-lJbkuc"
}
```

## Updating the DID Again

Let's generate a third key to rotate in for some verification methods.  In JWK format, the new private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "py1OHje9GMGdHPap0r-1gcMq0OOUFiDKjDrQxZfV80U",
  "d": "maWiBh51R5N6e4wCiPt-TEFYuzvK1__fx3l22ZafLUM"
}
```

Updated DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
  "selfHash": "uHiC9fL7JkWa2rkm6MelJGxTlAXFcwuJuJ4l0gq_FaJH5aA",
  "prevDIDDocumentSelfHash": "uHiCGrkkj7tWJ5F00DHLmyLtJszjRFjSICIcQlbrAdGVNog",
  "updateRules": {
    "key": "u7QGSG5ZpQrL6TeCsKNgsKWGFVoA0rKhImymHIuJzeJM-_w"
  },
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRR3FIM016ZkE0Y1RJYURFbm11bS1ZWEVhQ25JdmVqRHpWQW5NUDE2MHRjYmciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..BFsXOEYzzcXl416IVfZl52drKpPBWJWj0T-WkuNchcJNT-0hGdQAGvlcmEtqrV5lYSOF5ZobbZgmFcptAoMsDw"
  ],
  "validFrom": "2025-10-03T03:24:07.458363778Z",
  "versionId": 2,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "m7AuUCD1LhpiPhAOvNZyvbpM75PgUhdQqFKLCkSiXT4"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#2",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#2",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "py1OHje9GMGdHPap0r-1gcMq0OOUFiDKjDrQxZfV80U"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg#1",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "eyvv0Rmvr8SFkv0mSKGai_ZWQpSv5APmPY1s0OwQo9k"
      }
    }
  ],
  "authentication": [
    "#0",
    "#1"
  ],
  "assertionMethod": [
    "#0"
  ],
  "keyAgreement": [
    "#2"
  ],
  "capabilityInvocation": [
    "#2"
  ],
  "capabilityDelegation": [
    "#0"
  ]
}
```

Note that the `proofs` field contains signatures (in JWS format) that are to be validated and used with the `updateRules` field of the previous DID document to verify update authorization.  Note that the JWS proof has a detached payload, and decodes as:

```json
{
  "header": {
    "alg": "Ed25519",
    "b64": false,
    "crit": [
      "b64"
    ],
    "kid": "u7QGqH3MzfA4cTIaDEnmum-YXEaCnIvejDzVAnMP160tcbg"
  },
  "payload": null,
  "signature": "BFsXOEYzzcXl416IVfZl52drKpPBWJWj0T-WkuNchcJNT-0hGdQAGvlcmEtqrV5lYSOF5ZobbZgmFcptAoMsDw"
}
```

The associated DID document metadata (at the time of DID update) is:

```json
{
  "created": "2025-10-03T03:24:07.372913003Z",
  "nextUpdate": null,
  "nextVersionId": null,
  "updated": "2025-10-03T03:24:07.458363778Z",
  "versionId": 2
}
```

Similarly, the DID document metadata associated with the previous DID document has now become:

```json
{
  "created": "2025-10-03T03:24:07.372913003Z",
  "nextUpdate": "2025-10-03T03:24:07.458363778Z",
  "nextVersionId": 2,
  "updated": "2025-10-03T03:24:07.458363778Z",
  "versionId": 2
}
```

However, the DID document metadata associated with the root DID document has now become:

```json
{
  "created": "2025-10-03T03:24:07.372913003Z",
  "nextUpdate": "2025-10-03T03:24:07.380981642Z",
  "nextVersionId": 1,
  "updated": "2025-10-03T03:24:07.458363778Z",
  "versionId": 2
}
```

We set the `kid` field of each private JWK to point to the current DID document:

```json
{
  "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg?selfHash=uHiC9fL7JkWa2rkm6MelJGxTlAXFcwuJuJ4l0gq_FaJH5aA&versionId=2#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "m7AuUCD1LhpiPhAOvNZyvbpM75PgUhdQqFKLCkSiXT4",
  "d": "UmBDdU_9oHmb05riF8X-_bruTOvQHjUm5fNH_e_sV_s"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg?selfHash=uHiC9fL7JkWa2rkm6MelJGxTlAXFcwuJuJ4l0gq_FaJH5aA&versionId=2#1",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "eyvv0Rmvr8SFkv0mSKGai_ZWQpSv5APmPY1s0OwQo9k",
  "d": "H0iD_50oSOukrGxHfjwYyoG-uLVTVvE1BMkg-lJbkuc"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiDGDMhFBQmegii_Efm15eegRyDVLL_X5VUrm6xi-e46xg?selfHash=uHiC9fL7JkWa2rkm6MelJGxTlAXFcwuJuJ4l0gq_FaJH5aA&versionId=2#2",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "py1OHje9GMGdHPap0r-1gcMq0OOUFiDKjDrQxZfV80U",
  "d": "maWiBh51R5N6e4wCiPt-TEFYuzvK1__fx3l22ZafLUM"
}
```
