# Example: DID Microledger

This example can be run via command:

    cargo test -p did-webplus-core --all-features -- --nocapture test_did_update_sign_and_verify

## Example DID Documents

Here is an example of the DID documents in the microledger for a DID.

Root DID document (`versionId` 0):

```json
{
  "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
  "selfHash": "uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
  "updateRules": {
    "hashedKey": "uHiCMmFumKCTx6yxWPtoRM_VZj4DvdcHs2KEBK941pr8SXQ"
  },
  "validFrom": "2025-11-19T01:43:26.979Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ&versionId=0#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ&versionId=0#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "iR2bJQmYXszbiuW1yfeRmLtBkGsEczp99ZfEuQSPxwM"
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

Note that the `proofs` field is omitted since no proofs are required for the root DID document.  However, they MAY be present.

Next DID Document (`versionId` 1), in particular having new `updateRules`:

```json
{
  "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
  "selfHash": "uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw",
  "prevDIDDocumentSelfHash": "uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
  "updateRules": {
    "key": "u7QF0zsY-DxwlvuzDsosc0ZgD5drHhvNHXVkxwDDCMZHSIQ"
  },
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRzJPMlZtMjJlMWc0djZWUnhqWTlRZ205WHFKQUtmX2IzY0g2T2M0UjBiaHciLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..gjcKygeSmc9XC8h6Eosu1zPkjVF9_vPTI5Dm0PbNT7UZU4GvfvN1NsVEBWcXTEcCL22CW1ID5rb3SmjtsJnxBg"
  ],
  "validFrom": "2025-11-19T01:43:26.992Z",
  "versionId": 1,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "I87S--BfzauBtdJ4FkYLj9-bOF8gwj6iOMIx_lE-vhM"
      }
    },
    {
      "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ?selfHash=uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw&versionId=1#1",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "iR2bJQmYXszbiuW1yfeRmLtBkGsEczp99ZfEuQSPxwM"
      }
    }
  ],
  "authentication": [
    "#0"
  ],
  "assertionMethod": [
    "#1"
  ],
  "keyAgreement": [
    "#1"
  ],
  "capabilityInvocation": [
    "#0"
  ],
  "capabilityDelegation": [
    "#1"
  ]
}
```

Note that the element in the `proofs` field is a JWS whose header decodes as:

```json
{
  "alg": "Ed25519",
  "kid": "u7QG2O2Vm22e1g4v6VRxjY9Qgm9XqJAKf_b3cH6Oc4R0bhw",
  "crit": [
    "b64"
  ],
  "b64": false
}
```

Note that the hash of the `kid` field of the JWS header is `uHiCMmFumKCTx6yxWPtoRM_VZj4DvdcHs2KEBK941pr8SXQ` which should match the `hashedKey` field of the previous DID Document's `updateRules`.

Next DID Document (`versionId` 2), which shows how to deactivate a DID by setting `updateRules` to `{}`:

```json
{
  "id": "did:webplus:example.com:uHiAgZ9Z9FJ38ZGeQRZoFxxXfbpvRsg2DuPXJ5vzR1Uy3HQ",
  "selfHash": "uHiCrJkmyeDz01JHbmu-ft17Gwx11Les974G0BIV9fGWoDQ",
  "prevDIDDocumentSelfHash": "uHiCH05FmexvfpT8lxesItafqipzHvm_npUt4PRRCc8scEw",
  "updateRules": {},
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRjB6c1ktRHh3bHZ1ekRzb3NjMFpnRDVkckhodk5IWFZreHdERENNWkhTSVEiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..qBBCb1-4OHtnfyV_0KrUBpDE0aXhjBkYmCT5h7A0vtYtCGBVhfjUIRCrj3rJeO5h3N627uSdFcj2308Iaf6fAA"
  ],
  "validFrom": "2025-11-19T01:43:27.032Z",
  "versionId": 2,
  "verificationMethod": [],
  "authentication": [],
  "assertionMethod": [],
  "keyAgreement": [],
  "capabilityInvocation": [],
  "capabilityDelegation": []
}
```

Removing all verification methods from a deactivated DID is RECOMMENDED so that no unrevocable keys are left in the DID document, but is not required.  Note that the element in the `proofs` field is a JWS whose header decodes as:

```json
{
  "alg": "Ed25519",
  "kid": "u7QF0zsY-DxwlvuzDsosc0ZgD5drHhvNHXVkxwDDCMZHSIQ",
  "crit": [
    "b64"
  ],
  "b64": false
}
```

Note that the `kid` field of the JWS header matches the `key` field of the previous DID Document's `updateRules`.
