# Example: Signature Generation With Witness

This example can be run via command:

    cargo test -p did-webplus-core --all-features -- --nocapture test_signature_generation_with_witness

By specifying the `versionId` and `selfHash` query params in the `kid` field of a signature (header), the signer is committing to a specific DID document version having a specific `selfHash` value.  This acts as a witness in a limited way, making forking a DID microledger much more difficult.  Note that use of a Verifiable Data Gateway (described elsewhere) is the recommended way for preventing signature repudiation and forking of DIDs.

## Key Generation and DID Creation

We generate a private key and create a DID using the public key for the verification methods.  The generated private key is:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "UDfcxn5tiXG7f9J0e0XQxsTTk9IciiLDLpqmXduOjZc",
  "d": "Kl1O8viuVxsyb_Nxsh4FpyIeWMH1NxKn4-ANJ9HwIpk"
}
```

Root DID document (represented in 'pretty' JSON for readability; actual DID document is compact JSON):

```json
{
  "id": "did:webplus:example.com:uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg",
  "selfHash": "uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg",
  "updateRules": {
    "key": "u7QFQN9zGfm2Jcbt_0nR7RdDGxNOT0hyKIsMumqZd246Nlw"
  },
  "validFrom": "2025-10-03T18:56:01.126Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "UDfcxn5tiXG7f9J0e0XQxsTTk9IciiLDLpqmXduOjZc"
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

We set the private JWK's `kid` field (key ID) to include the query params and fragment, so that signatures produced by this private JWK identify which DID document was current as of signing, as well as identify which specific key was used to produce the signature (the alternative would be to attempt to verify the signature against all applicable public keys listed in the DID document).  The private JWK is now:

```json
{
  "kid": "did:webplus:example.com:uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg?selfHash=uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg&versionId=0#0",
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "UDfcxn5tiXG7f9J0e0XQxsTTk9IciiLDLpqmXduOjZc",
  "d": "Kl1O8viuVxsyb_Nxsh4FpyIeWMH1NxKn4-ANJ9HwIpk"
}
```

## Signature Generation

We'll sign a JSON payload and produce a JWS.  The payload is:

```json
{"HIPPOS":"much better than OSTRICHES"}
```

The resulting JWS is:

    eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmV4YW1wbGUuY29tOnVIaUIzMU9qN3NFWmNnT3BIMHJfeUJjUWZaVlZBREN1UDVvV08yUTR5SHVBc0pnP3NlbGZIYXNoPXVIaUIzMU9qN3NFWmNnT3BIMHJfeUJjUWZaVlZBREN1UDVvV08yUTR5SHVBc0pnJnZlcnNpb25JZD0wIzAifQ.eyJISVBQT1MiOiJtdWNoIGJldHRlciB0aGFuIE9TVFJJQ0hFUyJ9.QjyRn0FTFy0SINeJwN3i2t11Au2dpE6BmchRUHBNGZxIlTZTaNhGIzts2-ghcEBiFm7AjSS60FdKg_FlZiUEBA

Decoding the JWS, the header is:

```json
{
  "alg": "EdDSA",
  "kid": "did:webplus:example.com:uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg?selfHash=uHiB31Oj7sEZcgOpH0r_yBcQfZVVADCuP5oWO2Q4yHuAsJg&versionId=0#0"
}
```

When this JWS is verified by another party, they will resolve the DID document and key specified by the `kid` field.  This DID document resolution involves verifying the DID microledger up through the specified DID document (in real applications, this will be handled by a Verifiable Data Gateway which retrieves and verifies DID microledgers ahead of time).  Once the DID microledger is verified, the JWS can be verified against the public key listed in the DID document.  The DID resolution will also produce the DID document metadata, which indicates if the resolved DID document is the current DID document or not.  Depending on the particular use case, the currency of the signing key may or may not be relevant.
