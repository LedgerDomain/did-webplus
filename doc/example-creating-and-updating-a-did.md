# Example: Creating and Updating a DID

This example can be run via command:

    cargo test -p did-webplus-mock --all-features -- --nocapture test_example_creating_and_updating_a_did

## Creating a DID

For now, let's generate a single Ed25519 key to use in all the verification methods for the DID we will create.  In JWK format, the private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ",
  "d": "QnHzhmP0Koud9_KZmJPBgx3liXD7hszwTpUKkYOxTbA"
}
```

We'll also need a key that is authorized to update the DID document.  In publicKeyMultibase format, the public key is:

```
u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg
```

Creating a DID produces the root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
  "selfHash": "uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
  "updateRules": {
    "key": "u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg"
  },
  "validFrom": "2025-11-19T01:21:47.699Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w&versionId=0#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w&versionId=0#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ"
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
  "created": "2025-11-19T01:21:47Z",
  "createdMilliseconds": "2025-11-19T01:21:47.699Z",
  "updated": "2025-11-19T01:21:47Z",
  "updatedMilliseconds": "2025-11-19T01:21:47.699Z",
  "versionId": "0",
  "deactivated": false
}
```

We set the private JWK's `kid` field (key ID) to match that of its public JWK's `kid` field in the DID document (in particular, including the query params `selfHash` and `versionId`), so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:

```json
{
  "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w&versionId=0#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ",
  "d": "QnHzhmP0Koud9_KZmJPBgx3liXD7hszwTpUKkYOxTbA"
}
```

## Updating the DID

Let's generate another key to rotate in for some verification methods.  In JWK format, the new private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
  "d": "MpFvO25_pQbC3APLdNJi_-95mShEtaXG151Pardsy6s"
}
```

A new update key is also needed.  In publicKeyMultibase format, the new public key is:

```
u7QFNzTwiEH-gYlFQ_jb01lEFnWnyZPzq-rcehFEbF-rPFg
```

Updating a DID produces the next DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
  "selfHash": "uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q",
  "prevDIDDocumentSelfHash": "uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
  "updateRules": {
    "key": "u7QFNzTwiEH-gYlFQ_jb01lEFnWnyZPzq-rcehFEbF-rPFg"
  },
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRkNXS2FXTlE1RnNOU2hPOEJsWndqSGE1eGtHbGVlRVRLd3UtdmpmMVNaWGciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..DlqKjcvzBqMk8fE0AMqOr1Lnj6NgiMTv6iZMFWxHHWYLRz2KFVs9uTCVUfRrEBS2FAqLWY2u2lve8TNopSUkBA"
  ],
  "validFrom": "2025-11-19T01:21:47.715Z",
  "versionId": 1,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#1",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg"
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
    "kid": "u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg"
  },
  "payload": null,
  "signature": "DlqKjcvzBqMk8fE0AMqOr1Lnj6NgiMTv6iZMFWxHHWYLRz2KFVs9uTCVUfRrEBS2FAqLWY2u2lve8TNopSUkBA"
}
```

The associated DID document metadata (at the time of DID update) is:

```json
{
  "created": "2025-11-19T01:21:47Z",
  "createdMilliseconds": "2025-11-19T01:21:47.699Z",
  "updated": "2025-11-19T01:21:47Z",
  "updatedMilliseconds": "2025-11-19T01:21:47.715Z",
  "versionId": "1",
  "deactivated": false
}
```

However, the DID document metadata associated with the root DID document has now become:

```json
{
  "created": "2025-11-19T01:21:47Z",
  "createdMilliseconds": "2025-11-19T01:21:47.699Z",
  "nextUpdate": "2025-11-19T01:21:47Z",
  "nextUpdateMilliseconds": "2025-11-19T01:21:47.715Z",
  "nextVersionId": "1",
  "updated": "2025-11-19T01:21:47Z",
  "updatedMilliseconds": "2025-11-19T01:21:47.715Z",
  "versionId": "1",
  "deactivated": false
}
```

We set/update the `kid` field of each private JWK to match that of the public JWK in the updated DID document:

```json
{
  "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ",
  "d": "QnHzhmP0Koud9_KZmJPBgx3liXD7hszwTpUKkYOxTbA"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q&versionId=1#1",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
  "d": "MpFvO25_pQbC3APLdNJi_-95mShEtaXG151Pardsy6s"
}
```

## Updating the DID Again

Let's generate a third key to rotate in for some verification methods.  In JWK format, the new private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "yInsmsZAFa3-z16fj_jADU0jq22XIGLiJOKBWOL-9sw",
  "d": "ylSTkp5eckhJeGIdSijSjLP73PyP-LtQIugGbem9puQ"
}
```

Updated DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
  "selfHash": "uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg",
  "prevDIDDocumentSelfHash": "uHiCB0zZPRtP5SRrRj-dHe8DxkVAhdUZqEaRZEJ7-rSaa5Q",
  "updateRules": {
    "key": "u7QHRFrSIiqny7_FrLze0VF1xXgjHp0_5fzhlB2bfwLOYag"
  },
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRk56VHdpRUgtZ1lsRlFfamIwMWxFRm5XbnlaUHpxLXJjZWhGRWJGLXJQRmciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..SjRoWc9NlZrjqHu_eECRaqk57VVVeenk6YQgo7FYtBrO66O9_YOdKYJAo2dHOhSLDpht92YmUfC0HsWMrOH1BQ"
  ],
  "validFrom": "2025-11-19T01:21:47.766Z",
  "versionId": 2,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#2",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#2",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "yInsmsZAFa3-z16fj_jADU0jq22XIGLiJOKBWOL-9sw"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ"
      }
    },
    {
      "id": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#1",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg"
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
    "kid": "u7QFNzTwiEH-gYlFQ_jb01lEFnWnyZPzq-rcehFEbF-rPFg"
  },
  "payload": null,
  "signature": "SjRoWc9NlZrjqHu_eECRaqk57VVVeenk6YQgo7FYtBrO66O9_YOdKYJAo2dHOhSLDpht92YmUfC0HsWMrOH1BQ"
}
```

The associated DID document metadata (at the time of DID update) is:

```json
{
  "created": "2025-11-19T01:21:47Z",
  "createdMilliseconds": "2025-11-19T01:21:47.699Z",
  "updated": "2025-11-19T01:21:47Z",
  "updatedMilliseconds": "2025-11-19T01:21:47.766Z",
  "versionId": "2",
  "deactivated": false
}
```

Similarly, the DID document metadata associated with the previous DID document has now become:

```json
{
  "created": "2025-11-19T01:21:47Z",
  "createdMilliseconds": "2025-11-19T01:21:47.699Z",
  "nextUpdate": "2025-11-19T01:21:47Z",
  "nextUpdateMilliseconds": "2025-11-19T01:21:47.766Z",
  "nextVersionId": "2",
  "updated": "2025-11-19T01:21:47Z",
  "updatedMilliseconds": "2025-11-19T01:21:47.766Z",
  "versionId": "2",
  "deactivated": false
}
```

However, the DID document metadata associated with the root DID document has now become:

```json
{
  "created": "2025-11-19T01:21:47Z",
  "createdMilliseconds": "2025-11-19T01:21:47.699Z",
  "nextUpdate": "2025-11-19T01:21:47Z",
  "nextUpdateMilliseconds": "2025-11-19T01:21:47.715Z",
  "nextVersionId": "1",
  "updated": "2025-11-19T01:21:47Z",
  "updatedMilliseconds": "2025-11-19T01:21:47.766Z",
  "versionId": "2",
  "deactivated": false
}
```

We set/update the `kid` field of each private JWK to match that of the public JWK in the updated DID document:

```json
{
  "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "lZq_V0eF2PaFk07maitC6e-cMcCkYxkX1ugKRzFgodQ",
  "d": "QnHzhmP0Koud9_KZmJPBgx3liXD7hszwTpUKkYOxTbA"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#1",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "g2AYHF11v8WZyWajLDVAhN5mfSrMaXFsKdApmLY6vBg",
  "d": "MpFvO25_pQbC3APLdNJi_-95mShEtaXG151Pardsy6s"
}
```

```json
{
  "kid": "did:webplus:example.com:hey:uHiCa77-pRHbSiSIPSFO_EOlpw100j30VQnhWCXuwVMSA-w?selfHash=uHiBUjvHda3aTQVUPwTEvXqxOumNSd_aua0dTrjEBpZSelg&versionId=2#2",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "yInsmsZAFa3-z16fj_jADU0jq22XIGLiJOKBWOL-9sw",
  "d": "ylSTkp5eckhJeGIdSijSjLP73PyP-LtQIugGbem9puQ"
}
```
