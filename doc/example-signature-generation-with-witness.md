# Example: Signature Generation With Witness

This example can be run via command:

    cargo test --all-features --package did-webplus-core -- --nocapture test_signature_generation_with_witness

By specifying the `versionId` and `selfHash` query params in the `kid` field of a signature (header), the signer is committing to a specific DID document version having a specific `selfHash` value.  This acts as a witness in a limited way, making forking a DID microledger much more difficult.  Note that use of a Verifiable Data Gateway (described elsewhere) is the recommended way for preventing signature repudiation and forking of DIDs.

## Key Generation and DID Creation

We generate a private key and create a DID using the public key for the verification methods.  The generated private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "QBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM",
  "d": "dhs3jwc1zjM06ByXv4gkiIDIhw6aaQ-j7yXwsenx4kw"
}
```

Root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o",
  "selfHash": "EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o",
  "selfSignature": "0Bvx1TMz2WrQRBeRYl2CqJRZFoGUJK_AnsrVg-aC04K4CdRNfHX2S0sXRIKwfANKN-9yjI9h4E5_0EExVsYMtkBA",
  "selfSignatureVerifier": "DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM",
  "validFrom": "2023-09-29T07:00:26.208134325Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM",
        "kty": "OKP",
        "crv": "ed25519",
        "x": "QBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM"
      }
    }
  ],
  "authentication": [
    "#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM"
  ],
  "assertionMethod": [
    "#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM"
  ],
  "keyAgreement": [
    "#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM"
  ],
  "capabilityInvocation": [
    "#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM"
  ],
  "capabilityDelegation": [
    "#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM"
  ]
}
```

We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:

```json
{
  "kid": "did:webplus:example.com:EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o?versionId=0&selfHash=EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "QBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM",
  "d": "dhs3jwc1zjM06ByXv4gkiIDIhw6aaQ-j7yXwsenx4kw"
}
```

## Signature Generation

We'll sign a JSON payload and produce a JWS.  The payload is:

```json
{"HIPPOS":"much better than OSTRICHES"}
```

The resulting JWS is:

    eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmV4YW1wbGUuY29tOkVwRGdQTGZXTXN1dVNzQkZnVUlSTGc3RTZ3Y0tfOFhQSlJxdW5ORHlmRDlvP3ZlcnNpb25JZD0wJnNlbGZIYXNoPUVwRGdQTGZXTXN1dVNzQkZnVUlSTGc3RTZ3Y0tfOFhQSlJxdW5ORHlmRDlvI0RRQnhEcDMxamg4MjRRYlJOSHppUUN3N2RoMnlJT0phOTN3d05YWkpXQ1NNIn0.eyJISVBQT1MiOiJtdWNoIGJldHRlciB0aGFuIE9TVFJJQ0hFUyJ9.e968c268HCupGt6oPI22DnFfWCYBcb9-j2meyGKqEzYxbUlVgdYmdwve6kxlgjpvKvGJsLtS83Nmgtt41q8uAQ

Decoding the JWS, the header is:

```json
{
  "alg": "EdDSA",
  "kid": "did:webplus:example.com:EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o?versionId=0&selfHash=EpDgPLfWMsuuSsBFgUIRLg7E6wcK_8XPJRqunNDyfD9o#DQBxDp31jh824QbRNHziQCw7dh2yIOJa93wwNXZJWCSM"
}
```

When this JWS is verified by another party, they will resolve the DID document and key specified by the `kid` field.  This DID document resolution involves verifying the DID microledger up through the specified DID document (in real applications, this will be handled by a Verifiable Data Gateway which retrieves and verifies DID microledgers ahead of time).  Once the DID microledger is verified, the JWS can be verified against the public key listed in the DID document.  The DID resolution will also produce the DID document metadata, which indicates if the resolved DID document is the current DID document or not.  Depending on the particular use case, the currency of the signing key may or may not be relevant.
