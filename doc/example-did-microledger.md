# Example: DID Microledger

This example can be run via command:

    cargo test -p did-webplus-core --all-features -- --nocapture test_did_update_sign_and_verify

## Example DID Documents

Here is an example of the DID documents in the microledger for a DID.

Root DID document (`versionId` 0):

```json
{
  "id": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA",
  "selfHash": "uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA",
  "updateRules": {
    "hashedKey": "uHiALDuivdNdHulnKNQCnF7_btEO2pn8pejIc4xKPLBUyzA"
  },
  "validFrom": "2025-10-03T19:26:29.56Z",
  "versionId": 0,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "jUBNyWh6vrvC551iYR9g6R0awx1eGxDDlHfR3gG2V1g"
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
  "id": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA",
  "selfHash": "uHiBel_fCXh6jHWrnLRL0TjR3VpgeEGh_ZAALu91bknParA",
  "prevDIDDocumentSelfHash": "uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA",
  "updateRules": {
    "key": "u7QGNAb4V8rfeWgnKBFlOg-hNpyvRdhneRnI8aUKPziqKbA"
  },
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRSERjOGNUSFlqTEVZOUx0QTZzczdyN1BqWGRmSEZyOTB5SUo3Y3pfSEYxakEiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..lgQjZvV52dqKqM59tx6qMopeiSTU6mU4X11bpe5MzGK1xLljcoQT8qWYk2UyV6eKWkYI3UNWRL7piKxVfIWJBQ"
  ],
  "validFrom": "2025-10-03T19:26:29.567Z",
  "versionId": 1,
  "verificationMethod": [
    {
      "id": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA#1",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA#1",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "jUBNyWh6vrvC551iYR9g6R0awx1eGxDDlHfR3gG2V1g"
      }
    },
    {
      "id": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA#0",
      "type": "JsonWebKey2020",
      "controller": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA",
      "publicKeyJwk": {
        "kid": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA#0",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "G8fiCRSTe7yTuI8gVM4qcUJ-KsNdQb53eMwCfCtMwmE"
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
  "kid": "u7QHDc8cTHYjLEY9LtA6ss7r7PjXdfHFr90yIJ7cz_HF1jA",
  "crit": [
    "b64"
  ],
  "b64": false
}
```

Note that the hash of the `kid` field of the JWS header is `uHiALDuivdNdHulnKNQCnF7_btEO2pn8pejIc4xKPLBUyzA` which should match the `hashedKey` field of the previous DID Document's `updateRules`.

Next DID Document (`versionId` 2), which shows how to deactivate a DID by setting `updateRules` to `{}`:

```json
{
  "id": "did:webplus:example.com:uHiBbwc0wsYWMlHZMw0FWia3tmMMaVqIGBME0MTzcbMn6gA",
  "selfHash": "uHiBbvcmeBatdxnlQHvdojNtFqC57lAoTSmnZvr8UmatXdA",
  "prevDIDDocumentSelfHash": "uHiBel_fCXh6jHWrnLRL0TjR3VpgeEGh_ZAALu91bknParA",
  "updateRules": {},
  "proofs": [
    "eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRR05BYjRWOHJmZVdnbktCRmxPZy1oTnB5dlJkaG5lUm5JOGFVS1B6aXFLYkEiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..5pro_jMfX9ZJL4Ki76PniiH1HwErmbJNEC6lerQSH3j77tOlQKxHM1cL2WjWOxyFTW4fOLLgkNWXP6x5BsISAg"
  ],
  "validFrom": "2025-10-03T19:26:29.61Z",
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
  "kid": "u7QGNAb4V8rfeWgnKBFlOg-hNpyvRdhneRnI8aUKPziqKbA",
  "crit": [
    "b64"
  ],
  "b64": false
}
```

Note that the `kid` field of the JWS header matches the `key` field of the previous DID Document's `updateRules`.
