# Example: Creating and Updating a DID

This example can be run via command:

    cargo test -p did-webplus-mock --all-features -- --nocapture test_example_creating_and_updating_a_did

## Creating a DID

For now, let's generate a single Ed25519 key to use in all the verification methods for the DID we will create.  In JWK format, the private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "Uus_ouGx6QKMNS2WjjLs1ZLO-rRlJgBLTEU3WLJriJY",
  "d": "fHp0PHftult-W4AeCHOe7f7vApoG-YM2dC4JN9fotg0"
}
```

We'll also need a key that is authorized to update the DID document.  In publicKeyMultibase format, the public key is:

```
u7QHjMyU1-94d-7PNbtiqUZ5H3Zy07P5IaxFXGPTKuHWgdw
```

Creating a DID produces the root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
  "selfHash": "uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
  "updateRules": {
    "key": "u7QHjMyU1-94d-7PNbtiqUZ5H3Zy07P5IaxFXGPTKuHWgdw"
  },
  "validFrom": "2025-10-03T18:58:13.971Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "Uus_ouGx6QKMNS2WjjLs1ZLO-rRlJgBLTEU3WLJriJY"
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
  "created": "2025-10-03T18:58:13.971Z",
  "nextUpdate": null,
  "nextVersionId": null,
  "updated": "2025-10-03T18:58:13.971Z",
  "versionId": 0
}
```

We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:

```json
{
  "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ?selfHash=uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ&versionId=0#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "Uus_ouGx6QKMNS2WjjLs1ZLO-rRlJgBLTEU3WLJriJY",
  "d": "fHp0PHftult-W4AeCHOe7f7vApoG-YM2dC4JN9fotg0"
}
```

## Updating the DID

Let's generate another key to rotate in for some verification methods.  In JWK format, the new private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "FaaB4vWtZCVvpWC7kXuzFctavbqASQO_6aQgEwj66H4",
  "d": "gh1Szcv5L4eu17B1n9vRRGyZ8WKTUsWGqsb3_0aDI0s"
}
```

A new update key is also needed.  In publicKeyMultibase format, the new public key is:

```
u7QGlxxkLvHrDL8mcm1pwr2Q9pNRYEA4Z0tm_OBQ2L3LWyg
```

Updating a DID produces the next DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
  "selfHash": "uHiANbuUyuO_zTwgo_k430cK0M_wGpHa8otX_7TgxIAFshw",
  "prevDIDDocumentSelfHash": "uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
  "updateRules": {
    "key": "u7QGlxxkLvHrDL8mcm1pwr2Q9pNRYEA4Z0tm_OBQ2L3LWyg"
  },
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRSGpNeVUxLTk0ZC03UE5idGlxVVo1SDNaeTA3UDVJYXhGWEdQVEt1SFdnZHciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..WxADtzj4sWspqNIyoe5zQC5P41Bf2OF8cLPuWH1tzlMKiLc2phGWWjCQfN1UzDK0YxfFaSuFt2vYIpfR87U2Bw"
  ],
  "validFrom": "2025-10-03T18:58:13.978Z",
  "versionId": 1,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "Uus_ouGx6QKMNS2WjjLs1ZLO-rRlJgBLTEU3WLJriJY"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#1",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "FaaB4vWtZCVvpWC7kXuzFctavbqASQO_6aQgEwj66H4"
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
    "kid": "u7QHjMyU1-94d-7PNbtiqUZ5H3Zy07P5IaxFXGPTKuHWgdw"
  },
  "payload": null,
  "signature": "WxADtzj4sWspqNIyoe5zQC5P41Bf2OF8cLPuWH1tzlMKiLc2phGWWjCQfN1UzDK0YxfFaSuFt2vYIpfR87U2Bw"
}
```

The associated DID document metadata (at the time of DID update) is:

```json
{
  "created": "2025-10-03T18:58:13.971Z",
  "nextUpdate": null,
  "nextVersionId": null,
  "updated": "2025-10-03T18:58:13.978Z",
  "versionId": 1
}
```

However, the DID document metadata associated with the root DID document has now become:

```json
{
  "created": "2025-10-03T18:58:13.971Z",
  "nextUpdate": "2025-10-03T18:58:13.978Z",
  "nextVersionId": 1,
  "updated": "2025-10-03T18:58:13.978Z",
  "versionId": 1
}
```

We set the `kid` field of each private JWK to point to the current DID document:

```json
{
  "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ?selfHash=uHiANbuUyuO_zTwgo_k430cK0M_wGpHa8otX_7TgxIAFshw&versionId=1#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "Uus_ouGx6QKMNS2WjjLs1ZLO-rRlJgBLTEU3WLJriJY",
  "d": "fHp0PHftult-W4AeCHOe7f7vApoG-YM2dC4JN9fotg0"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ?selfHash=uHiANbuUyuO_zTwgo_k430cK0M_wGpHa8otX_7TgxIAFshw&versionId=1#1",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "FaaB4vWtZCVvpWC7kXuzFctavbqASQO_6aQgEwj66H4",
  "d": "gh1Szcv5L4eu17B1n9vRRGyZ8WKTUsWGqsb3_0aDI0s"
}
```

## Updating the DID Again

Let's generate a third key to rotate in for some verification methods.  In JWK format, the new private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "xtQxmVG5Iebooxl-QE1b0rCel8DoG_9N8ycnDsCUNXo",
  "d": "jrezMR2brpp4c3Vq8rWx7mhwiDevqkq2ShZXBdFKtEs"
}
```

Updated DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
  "selfHash": "uHiDy7BDn0_-K4jYnhvUDJ38GmEaK2lESTVfwuiHemuXibQ",
  "prevDIDDocumentSelfHash": "uHiANbuUyuO_zTwgo_k430cK0M_wGpHa8otX_7TgxIAFshw",
  "updateRules": {
    "key": "u7QFGzX5sMj792KhdJs7e9r3OJ6KpOy6WtBk7MfE1QTEkTQ"
  },
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRR2x4eGtMdkhyREw4bWNtMXB3cjJROXBOUllFQTRaMHRtX09CUTJMM0xXeWciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..qIJSY9dkmrConVc5lEx4ArHasiz5AB4eRQzrFn15Y22BI4MiC3qchn-8RPUVTMyzEjHIC_wHCLafh2lQPoTvAw"
  ],
  "validFrom": "2025-10-03T18:58:14.032Z",
  "versionId": 2,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#2",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#2",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "xtQxmVG5Iebooxl-QE1b0rCel8DoG_9N8ycnDsCUNXo"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "Uus_ouGx6QKMNS2WjjLs1ZLO-rRlJgBLTEU3WLJriJY"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ#1",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "FaaB4vWtZCVvpWC7kXuzFctavbqASQO_6aQgEwj66H4"
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
    "kid": "u7QGlxxkLvHrDL8mcm1pwr2Q9pNRYEA4Z0tm_OBQ2L3LWyg"
  },
  "payload": null,
  "signature": "qIJSY9dkmrConVc5lEx4ArHasiz5AB4eRQzrFn15Y22BI4MiC3qchn-8RPUVTMyzEjHIC_wHCLafh2lQPoTvAw"
}
```

The associated DID document metadata (at the time of DID update) is:

```json
{
  "created": "2025-10-03T18:58:13.971Z",
  "nextUpdate": null,
  "nextVersionId": null,
  "updated": "2025-10-03T18:58:14.032Z",
  "versionId": 2
}
```

Similarly, the DID document metadata associated with the previous DID document has now become:

```json
{
  "created": "2025-10-03T18:58:13.971Z",
  "nextUpdate": "2025-10-03T18:58:14.032Z",
  "nextVersionId": 2,
  "updated": "2025-10-03T18:58:14.032Z",
  "versionId": 2
}
```

However, the DID document metadata associated with the root DID document has now become:

```json
{
  "created": "2025-10-03T18:58:13.971Z",
  "nextUpdate": "2025-10-03T18:58:13.978Z",
  "nextVersionId": 1,
  "updated": "2025-10-03T18:58:14.032Z",
  "versionId": 2
}
```

We set the `kid` field of each private JWK to point to the current DID document:

```json
{
  "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ?selfHash=uHiDy7BDn0_-K4jYnhvUDJ38GmEaK2lESTVfwuiHemuXibQ&versionId=2#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "Uus_ouGx6QKMNS2WjjLs1ZLO-rRlJgBLTEU3WLJriJY",
  "d": "fHp0PHftult-W4AeCHOe7f7vApoG-YM2dC4JN9fotg0"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ?selfHash=uHiDy7BDn0_-K4jYnhvUDJ38GmEaK2lESTVfwuiHemuXibQ&versionId=2#1",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "FaaB4vWtZCVvpWC7kXuzFctavbqASQO_6aQgEwj66H4",
  "d": "gh1Szcv5L4eu17B1n9vRRGyZ8WKTUsWGqsb3_0aDI0s"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiDQLgfBCe9ZAQeBPiDJWO74YKI_QHtpFyAuIRFpsb6nPQ?selfHash=uHiDy7BDn0_-K4jYnhvUDJ38GmEaK2lESTVfwuiHemuXibQ&versionId=2#2",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "xtQxmVG5Iebooxl-QE1b0rCel8DoG_9N8ycnDsCUNXo",
  "d": "jrezMR2brpp4c3Vq8rWx7mhwiDevqkq2ShZXBdFKtEs"
}
```
