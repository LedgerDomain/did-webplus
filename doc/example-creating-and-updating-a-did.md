# Example: Creating and Updating a DID

This example can be run via command:

    cargo test --all-features -- --nocapture test_example_creating_and_updating_a_did

## Creating a DID

For now, let's generate a single Ed25519 key to use in all the verification methods for the DID we will create.  In JWK format, the private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "ar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "d": "bt3fRVSQOBIZ6P2MpfzZ45_-6cTf48m1338ojX6MwKg"
}
```

Creating a DID produces the root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
  "selfHash": "EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
  "selfSignature": "0BuQYSLaLz_HBZulqOI_jH3T3BoKI_QZ9MHE58zzJKmT4M2FOMLW3OFCBJZ8k0jZaAY7YJzyk8finF1bICjXmUDQ",
  "selfSignatureVerifier": "Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "validFrom": "2023-09-29T10:01:29.860693793Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
        "kty": "OKP",
        "crv": "ed25519",
        "x": "ar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
      }
    }
  ],
  "authentication": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ],
  "assertionMethod": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ],
  "keyAgreement": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ],
  "capabilityInvocation": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ],
  "capabilityDelegation": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ]
}
```

Note that the `selfSignatureVerifier` field is a public key that is also found in the `capabilityInvocation` field.  This is the initial proof of control over the DID.

The associated DID document metadata (at the time of DID creation) is:

```json
{
  "created": "2023-09-29T10:01:29.860693793Z",
  "updated": "2023-09-29T10:01:29.860693793Z",
  "nextUpdate": null,
  "versionId": 0,
  "nextVersionId": null
}
```

We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:

```json
{
  "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=0&selfHash=EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "ar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "d": "bt3fRVSQOBIZ6P2MpfzZ45_-6cTf48m1338ojX6MwKg"
}
```

## Updating the DID

Let's generate another key to rotate in for some verification methods.  In JWK format, the new private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "DG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
  "d": "Owcwu8hCCKaFDf9hm8HTIm8rV5_ZBFGZ83IwX6tm_-k"
}
```

Updating a DID produces the next DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
  "selfHash": "EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY",
  "selfSignature": "0BECMc-xhI3T2eo0w2bSHT3Rr_hVV5Yt7S0ySzW4Rxxh15iR9ALvDUvXn7d7fB5cjT2f5ZROVcFmdj8NZ8snaXAw",
  "selfSignatureVerifier": "Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "prevDIDDocumentSelfHash": "EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
  "validFrom": "2023-09-29T10:01:29.896537517Z",
  "versionId": 1,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
        "kty": "OKP",
        "crv": "ed25519",
        "x": "DG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I"
      }
    },
    {
      "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
        "kty": "OKP",
        "crv": "ed25519",
        "x": "ar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
      }
    }
  ],
  "authentication": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
    "#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I"
  ],
  "assertionMethod": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ],
  "keyAgreement": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ],
  "capabilityInvocation": [
    "#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I"
  ],
  "capabilityDelegation": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ]
}
```

Note that the `selfSignatureVerifier` field is present in the previous (root) DID document's `capabilityInvocation` field.  This proves that the DID document was updated by an authorized entity.

The associated DID document metadata (at the time of DID update) is:

```json
{
  "created": "2023-09-29T10:01:29.860693793Z",
  "updated": "2023-09-29T10:01:29.896537517Z",
  "nextUpdate": null,
  "versionId": 1,
  "nextVersionId": null
}
```

However, the DID document metadata associated with the root DID document has now become:

```json
{
  "created": "2023-09-29T10:01:29.860693793Z",
  "updated": "2023-09-29T10:01:29.896537517Z",
  "nextUpdate": "2023-09-29T10:01:29.896537517Z",
  "versionId": 1,
  "nextVersionId": 1
}
```

We set the new private JWK's `kid` field as earlier:

```json
{
  "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1&selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "DG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
  "d": "Owcwu8hCCKaFDf9hm8HTIm8rV5_ZBFGZ83IwX6tm_-k"
}
```

And update the first private JWK's `kid` field to point to the current DID document:

```json
{
  "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1&selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "ar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "d": "bt3fRVSQOBIZ6P2MpfzZ45_-6cTf48m1338ojX6MwKg"
}
```

## Updating the DID Again

Let's generate a third key to rotate in for some verification methods.  In JWK format, the new private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs",
  "d": "NLf894QU-idKoBleNvpiSGqpvMQu5WOLmMG-6NHZy4s"
}
```

Updated DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
  "selfHash": "E-T4tNIrE7dFqZIgjHsVCoRS4S9rGQgRZidGXtcG35o8",
  "selfSignature": "0BAxr7qTk0DF35hUPCv9iyInBg2ubfyE5jFrBGJ0cPs5ecJIRfVQLRzGf-zSs8je0MDxDqGujVPlpNEjYY5iKVCA",
  "selfSignatureVerifier": "DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
  "prevDIDDocumentSelfHash": "EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY",
  "validFrom": "2023-09-29T10:01:29.96004546Z",
  "versionId": 2,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
        "kty": "OKP",
        "crv": "ed25519",
        "x": "ar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
      }
    },
    {
      "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
        "kty": "OKP",
        "crv": "ed25519",
        "x": "DG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I"
      }
    },
    {
      "id": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#D7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ#D7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs",
        "kty": "OKP",
        "crv": "ed25519",
        "x": "7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs"
      }
    }
  ],
  "authentication": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
    "#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I"
  ],
  "assertionMethod": [
    "#D7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs"
  ],
  "keyAgreement": [
    "#D7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs"
  ],
  "capabilityInvocation": [
    "#D7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs"
  ],
  "capabilityDelegation": [
    "#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE"
  ]
}
```

Note that the `selfSignatureVerifier` field is present in the previous (root) DID document's `capabilityInvocation` field.  This proves that the DID document was updated by an authorized entity.

The associated DID document metadata (at the time of DID update) is:

```json
{
  "created": "2023-09-29T10:01:29.860693793Z",
  "updated": "2023-09-29T10:01:29.96004546Z",
  "nextUpdate": null,
  "versionId": 2,
  "nextVersionId": null
}
```

Similarly, the DID document metadata associated with the previous DID document has now become:

```json
{
  "created": "2023-09-29T10:01:29.860693793Z",
  "updated": "2023-09-29T10:01:29.96004546Z",
  "nextUpdate": "2023-09-29T10:01:29.96004546Z",
  "versionId": 2,
  "nextVersionId": 2
}
```

However, the DID document metadata associated with the root DID document has now become:

```json
{
  "created": "2023-09-29T10:01:29.860693793Z",
  "updated": "2023-09-29T10:01:29.96004546Z",
  "nextUpdate": "2023-09-29T10:01:29.896537517Z",
  "versionId": 2,
  "nextVersionId": 1
}
```

We set the new private JWK's `kid` field as earlier:

```json
{
  "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=2&selfHash=E-T4tNIrE7dFqZIgjHsVCoRS4S9rGQgRZidGXtcG35o8#D7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "7Eh2dRf3_D_AVGHr7U9BXzPPb9w1Hd7b0AH_VOekHRs",
  "d": "NLf894QU-idKoBleNvpiSGqpvMQu5WOLmMG-6NHZy4s"
}
```

And update the first private JWK's `kid` field to point to the current DID document:

```json
{
  "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=2&selfHash=E-T4tNIrE7dFqZIgjHsVCoRS4S9rGQgRZidGXtcG35o8#Dar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "ar0F7zeNrtp2tGBplO2ZVCPyLHyxsWOAEv9i-5khnsE",
  "d": "bt3fRVSQOBIZ6P2MpfzZ45_-6cTf48m1338ojX6MwKg"
}
```

And update the first private JWK's `kid` field to point to the current DID document:

```json
{
  "kid": "did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=2&selfHash=E-T4tNIrE7dFqZIgjHsVCoRS4S9rGQgRZidGXtcG35o8#DDG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "DG7RxmBBNf9HaTpr75uSDNS5qpHVOG2WEjmf7T7wi-I",
  "d": "Owcwu8hCCKaFDf9hm8HTIm8rV5_ZBFGZ83IwX6tm_-k"
}
```
