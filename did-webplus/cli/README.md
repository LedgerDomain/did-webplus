# did-webplus-cli

The `did-webplus` commandline interface (CLI) tool provides all the basic client functionality, including:
-   A basic "edge" wallet that:
    -   Performs key management
    -   Creates and updates DIDs, thereby "controlling" those DIDs
    -   Signs things using its controlled DIDs
        -   JWS
        -   VJSON
-   `did:webplus` DID resolution
-   Verification operations on
    -   JWS
    -   VJSON
-   Basic `did:key` functionality:
    -   Generate a private key to a local file
    -   Show the `did:key` form of the public key associated with a private key
    -   Signs things using a private key
        -   JWS
        -   VJSON

An early overview of the concept of VJSON (Verifiable JSON) is available [here](https://docs.google.com/presentation/d/1DBPN-YoImfLQ5M3-csoR1ez1It0EmGvJrZuTGkmcWzo/edit?usp=sharing).  A working example is available [here](examples/vjson/contract).

## Installing the native binary

Ensure you're in the did-webplus-cli dir.  Then run:

    cargo install --path .

This will build and install the `did-webplus` binary to `~/.cargo/bin` (or wherever cargo is configured to install binaries), and should be accessible on your path.

## Building and running the dockerized CLI tool

The main reason this dockerized version of the CLI tool exists is so that it can run against the VDR and VDG running inside the docker network that is spun up by the docker-compose in [`did-webplus-vdg`](../vdg).  You must build and run that docker-compose before this dockerized did-webplus-cli tool is useful.

Ensure you're in the did-webplus-cli dir.

### Build

This will build the necessary docker images:

    make docker-build

### Run

First ensure the docker-compose in [`did-webplus-vdg`](../vdg) is running (see instructions there).

To run a shell in which you can run the `did-webplus` binary against the dockerized VDR and VDG, run:

    make shell

Note that this will (create and) mount your local filesystem's `~/.did-webplus.docker` directory under `~/.did-webplus` within the running container, so that the wallet in the container is persistent between runs.

Here is a sequence of commands that will exercise the various operations of the CLI tool.

#### Wallet-based DID Create

This command will create a new DID, along with an associated set of private keys, and publish the DID document to the VDR `http://fancy.net` (the VDR service running in the docker-compose).

    did-webplus wallet did create

It will print the fully-qualified DID (which means the query parameters that specify the selfHash and versionId of the latest DID document are present), e.g.

    did:webplus:fancy.net:El80wguYPqpC0Kr-nfImpxkYdqgXbYaN_FP2iP_czdU0?selfHash=El80wguYPqpC0Kr-nfImpxkYdqgXbYaN_FP2iP_czdU0&versionId=0

The DID is the portion before the `?`:

    did:webplus:fancy.net:El80wguYPqpC0Kr-nfImpxkYdqgXbYaN_FP2iP_czdU0

#### Wallet-based DID List

You can list the DIDs that the wallet controls:

    did-webplus wallet did list

E.g. output:

    ["did:webplus:fancy.net:El80wguYPqpC0Kr-nfImpxkYdqgXbYaN_FP2iP_czdU0"]

#### Wallet-based DID Update

This command will update the DID by rotating all of its associated keys and publishing the DID document to the VDR (which is specified by the DID itself):

    did-webplus wallet did update

It will print the updated, fully-qualified DID; notice the versionId value:

    did:webplus:fancy.net:El80wguYPqpC0Kr-nfImpxkYdqgXbYaN_FP2iP_czdU0?selfHash=EFqiIvXffUn2KYVtbEXZdVe_YTafosW1uiSE2XDEn7Ic&versionId=1

#### Wallet-based DID Sign JWS

Now produce a JWS that is signed by the DID:

    echo '{"blah": 123}' | did-webplus wallet did sign jws --key-purpose assertion-method

This will output the JWS:

    eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEcjc1dXZzWHNCNXV0WHZyMWVFblVhYnZfSnU0aXVkQ0JEa0dGVDVmLW51byJ9.eyJibGFoIjogMTIzfQo.HTXT7Z-PQsSOvQ2cDA2nl_Sg0C9XlSDGt944hpD-wAdv08QHh_revVontQoHYBgENulJQ3M5d3r0GtU9rggxDw

which decodes as:

    {
        "header": {
            "alg": "EdDSA",
            "kid": "did:webplus:fancy.net:El80wguYPqpC0Kr-nfImpxkYdqgXbYaN_FP2iP_czdU0?selfHash=EFqiIvXffUn2KYVtbEXZdVe_YTafosW1uiSE2XDEn7Ic&versionId=1#Dr75uvsXsB5utXvr1eEnUabv_Ju4iudCBDkGFT5f-nuo"
        },
        "payload": {
            "blah": 123
        },
        "signature": "HTXT7Z-PQsSOvQ2cDA2nl_Sg0C9XlSDGt944hpD-wAdv08QHh_revVontQoHYBgENulJQ3M5d3r0GtU9rggxDw"
    }

#### Verify JWS

Notice how the fully-qualified DID is used in the `"kid"` field of the JWS header.  This is used in verifying the JWS:

    echo eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEcjc1dXZzWHNCNXV0WHZyMWVFblVhYnZfSnU0aXVkQ0JEa0dGVDVmLW51byJ9.eyJibGFoIjogMTIzfQo.HTXT7Z-PQsSOvQ2cDA2nl_Sg0C9XlSDGt944hpD-wAdv08QHh_revVontQoHYBgENulJQ3M5d3r0GtU9rggxDw | did-webplus verify jws

If the JWS was successfully verified, it will print nothing and return with exit code 0 (success).  Otherwise the JWS failed verification and an error message will be printed and a nonzero exit code will be returned.

#### VJSON Self-Hash

Verifiable JSON (VJSON) will be detailed more later, but the TL;DR is that VJSON a self-hashed JSON blob that has 0 or more digital signatures in JWS form.  To create a VJSON with no signatures and only a self-hash, run:

    echo '{"some": [true, "fancy", "data"]}' | did-webplus vjson self-hash

The output is the same JSON blob but self-hashed.  Note that this output is deterministic, unlike the above examples that use a randomly-generated private key.

    {"selfHash":"EnqhPjuIiP8Dh1OmfdjC16LuYRKAsDTAUGY6POihRNa0","some":[true,"fancy","data"]}

#### VJSON Verify

This VJSON can be verified (note the necessary single quotes in the `echo` command):

    echo '{"selfHash":"EnqhPjuIiP8Dh1OmfdjC16LuYRKAsDTAUGY6POihRNa0","some":[true,"fancy","data"]}' | did-webplus vjson verify

If verified, it will print the verified VJSON and return with exit code 0 (success).  If invalid, it will print an error message and return with nonzero exit code.

#### Wallet-based DID Sign VJSON

Signed VJSON can be produced either from an plain JSON blob or an existing VJSON blob.  Signatures, which are JWS with detached payload, will be appended into the "proofs" field (which will be an array of JWS strings).  Signatures exclude the "proofs" field when signing, and furthermore set the self-hash slot(s) to the appropriate placeholder value before signing, so that the self-hash can be computed after the "proofs" field is re-included with the newly created signature.  This is so multiple signatures that all sign the same payload can be included in the VJSON.

Using the same JSON blob as the previous example:

    echo '{"some": [true, "fancy", "data"]}' | did-webplus wallet did sign vjson --key-purpose assertion-method

The output is the signed, self-hashed VJSON.

    {"proofs":["eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEcjc1dXZzWHNCNXV0WHZyMWVFblVhYnZfSnU0aXVkQ0JEa0dGVDVmLW51byJ9..fvHtWqHeRIpZmRIhbqLtO_S0JIem66TlCtabCe0ragqwyi9y6uEjPHCN-lVH6LroQlSLYYZ60idKjBfRB4bfBA"],"selfHash":"EPf9Dff9A-W14pSF8jtV4crqN_Vs0iYcYYZ0rQZ1bBxM","some":[true,"fancy","data"]}

Note that the JWS in the proofs field decodes as

    {
        "header": {
            "alg": "EdDSA",
            "kid": "did:webplus:fancy.net:El80wguYPqpC0Kr-nfImpxkYdqgXbYaN_FP2iP_czdU0?selfHash=EFqiIvXffUn2KYVtbEXZdVe_YTafosW1uiSE2XDEn7Ic&versionId=1#Dr75uvsXsB5utXvr1eEnUabv_Ju4iudCBDkGFT5f-nuo"
        },
        "payload": null,
        "signature": "fvHtWqHeRIpZmRIhbqLtO_S0JIem66TlCtabCe0ragqwyi9y6uEjPHCN-lVH6LroQlSLYYZ60idKjBfRB4bfBA"
    }

That `"payload": null` indicates that the JWS has a detached payload which is derived from the VJSON.  This VJSON can be verified:

    echo '{"proofs":["eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEcjc1dXZzWHNCNXV0WHZyMWVFblVhYnZfSnU0aXVkQ0JEa0dGVDVmLW51byJ9..fvHtWqHeRIpZmRIhbqLtO_S0JIem66TlCtabCe0ragqwyi9y6uEjPHCN-lVH6LroQlSLYYZ60idKjBfRB4bfBA"],"selfHash":"EPf9Dff9A-W14pSF8jtV4crqN_Vs0iYcYYZ0rQZ1bBxM","some":[true,"fancy","data"]}' | did-webplus vjson verify

Upon verification success, the VJSON blob will be printed and the process will return with exit code 0.

#### Wallet-based DID Sign VJSON (Append Another Signature)

This VJSON can be fed back in to add another signature.  Let's use a different key purpose so that it's a different signing key.

    echo '{"proofs":["eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEcjc1dXZzWHNCNXV0WHZyMWVFblVhYnZfSnU0aXVkQ0JEa0dGVDVmLW51byJ9..fvHtWqHeRIpZmRIhbqLtO_S0JIem66TlCtabCe0ragqwyi9y6uEjPHCN-lVH6LroQlSLYYZ60idKjBfRB4bfBA"],"selfHash":"EPf9Dff9A-W14pSF8jtV4crqN_Vs0iYcYYZ0rQZ1bBxM","some":[true,"fancy","data"]}' | did-webplus wallet did sign vjson --key-purpose authentication

The output VJSON now has two elements in the "proofs" array:

    {"proofs":["eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEcjc1dXZzWHNCNXV0WHZyMWVFblVhYnZfSnU0aXVkQ0JEa0dGVDVmLW51byJ9..fvHtWqHeRIpZmRIhbqLtO_S0JIem66TlCtabCe0ragqwyi9y6uEjPHCN-lVH6LroQlSLYYZ60idKjBfRB4bfBA","eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEYkR5cGZtcUNfeDZHUU0yOWhBRnhGZm41WTVDMzFRaUNBZHZWQXlqdlNacyJ9..kImKmgy1jxbZa1iUrXVT082xEWPssPDqqPeJsL5YRd9PX8Swo9T1sF3dbMcx2Dv35GHN-71wF3so04ePZfS8DA"],"selfHash":"EqtRKY6456uGvbvBGdxVFd1xusL_Bc0BJmApzc_VHatA","some":[true,"fancy","data"]}

The second JWS in the proofs field decodes as

    {
        "header": {
            "alg": "EdDSA",
            "kid": "did:webplus:fancy.net:El80wguYPqpC0Kr-nfImpxkYdqgXbYaN_FP2iP_czdU0?selfHash=EFqiIvXffUn2KYVtbEXZdVe_YTafosW1uiSE2XDEn7Ic&versionId=1#DbDypfmqC_x6GQM29hAFxFfn5Y5C31QiCAdvVAyjvSZs"
        },
        "payload": null,
        "signature": "kImKmgy1jxbZa1iUrXVT082xEWPssPDqqPeJsL5YRd9PX8Swo9T1sF3dbMcx2Dv35GHN-71wF3so04ePZfS8DA"
    }

#### VJSON Verify

To verify the VJSON:

    echo '{"proofs":["eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEcjc1dXZzWHNCNXV0WHZyMWVFblVhYnZfSnU0aXVkQ0JEa0dGVDVmLW51byJ9..fvHtWqHeRIpZmRIhbqLtO_S0JIem66TlCtabCe0ragqwyi9y6uEjPHCN-lVH6LroQlSLYYZ60idKjBfRB4bfBA","eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFbDgwd2d1WVBxcEMwS3ItbmZJbXB4a1lkcWdYYllhTl9GUDJpUF9jemRVMD9zZWxmSGFzaD1FRnFpSXZYZmZVbjJLWVZ0YkVYWmRWZV9ZVGFmb3NXMXVpU0UyWERFbjdJYyZ2ZXJzaW9uSWQ9MSNEYkR5cGZtcUNfeDZHUU0yOWhBRnhGZm41WTVDMzFRaUNBZHZWQXlqdlNacyJ9..kImKmgy1jxbZa1iUrXVT082xEWPssPDqqPeJsL5YRd9PX8Swo9T1sF3dbMcx2Dv35GHN-71wF3so04ePZfS8DA"],"selfHash":"EqtRKY6456uGvbvBGdxVFd1xusL_Bc0BJmApzc_VHatA","some":[true,"fancy","data"]}' | did-webplus vjson verify

Notice that the selfHash field has changed each time a proof was added.
-   With no `proofs` field, the `selfHash` field was `EnqhPjuIiP8Dh1OmfdjC16LuYRKAsDTAUGY6POihRNa0`.
-   With one element in `proofs`, the `selfHash` field was `EPf9Dff9A-W14pSF8jtV4crqN_Vs0iYcYYZ0rQZ1bBxM`.
-   With two elements in `proofs`, the `selfHash` field was `EqtRKY6456uGvbvBGdxVFd1xusL_Bc0BJmApzc_VHatA`.

This is because the self-hash is computed over the whole VJSON, including the `proofs` field.

#### DID-Key Generate

Finally, using a `did:webplus` DID may require contact with the VDR and/or VDG, and for testing and development purposes, it's often useful to use a static DID method that doesn't require any service for DID resolution.  In particular, `did:key`.  To generate a private key for use with `did:key`, run:

    did-webplus did-key generate --key-type ed25519

This will print the `did:key` form of the corresponding public key, e.g.

    did:key:z6MkrjypkHvMnBHUAJ9zp2qMPMyorjXqLcBMzG7bEXaangHz

#### DID-Key From-Private

If you need to print this public `did:key` again, run:

    did-webplus did-key from-private

and it will print:

    did:key:z6MkrjypkHvMnBHUAJ9zp2qMPMyorjXqLcBMzG7bEXaangHz

#### DID-Key Sign JWS

You can sign JWS and VJSON using `did:key`:

    echo '{"fancy": "stuff"}' | did-webplus did-key sign jws

Output, e.g.:

    eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3JqeXBrSHZNbkJIVUFKOXpwMnFNUE15b3JqWHFMY0JNekc3YkVYYWFuZ0h6I3o2TWtyanlwa0h2TW5CSFVBSjl6cDJxTVBNeW9yalhxTGNCTXpHN2JFWGFhbmdIeiJ9.eyJmYW5jeSI6ICJzdHVmZiJ9Cg.Vbw722V2dthZalWg_1o7JpF5bs8QHCXKYxqVQQtEQ2T_PfX6FOiAnmMX6UHWL0p3yJtRgHTuSgCeBEx5VX9LAA

which decodes into:

    {
        "header": {
            "alg": "EdDSA",
            "kid": "did:key:z6MkrjypkHvMnBHUAJ9zp2qMPMyorjXqLcBMzG7bEXaangHz#z6MkrjypkHvMnBHUAJ9zp2qMPMyorjXqLcBMzG7bEXaangHz"
        },
        "payload": {
            "fancy": "stuff"
        },
        "signature": "Vbw722V2dthZalWg_1o7JpF5bs8QHCXKYxqVQQtEQ2T_PfX6FOiAnmMX6UHWL0p3yJtRgHTuSgCeBEx5VX9LAA"
    }

Verify via:

    echo eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3JqeXBrSHZNbkJIVUFKOXpwMnFNUE15b3JqWHFMY0JNekc3YkVYYWFuZ0h6I3o2TWtyanlwa0h2TW5CSFVBSjl6cDJxTVBNeW9yalhxTGNCTXpHN2JFWGFhbmdIeiJ9.eyJmYW5jeSI6ICJzdHVmZiJ9Cg.Vbw722V2dthZalWg_1o7JpF5bs8QHCXKYxqVQQtEQ2T_PfX6FOiAnmMX6UHWL0p3yJtRgHTuSgCeBEx5VX9LAA | did-webplus verify jws

#### DID-Key Sign VJSON

Similarly,

    echo '{"fancy": "stuff"}' | did-webplus did-key sign vjson

Output, e.g.:

    {"fancy":"stuff","proofs":["eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3JqeXBrSHZNbkJIVUFKOXpwMnFNUE15b3JqWHFMY0JNekc3YkVYYWFuZ0h6I3o2TWtyanlwa0h2TW5CSFVBSjl6cDJxTVBNeW9yalhxTGNCTXpHN2JFWGFhbmdIeiJ9..Znk9Coho5DEnF7O6_pu61zxbSZqaC9tnWWkxfn3RQjK6U8V3nMInMixTTN9kJZJW25TscTFpcPQ_RXwDu1TIAQ"],"selfHash":"En3kmljhbgxaPq-PW7nN3WlMGDjebVDL92uuAIxlmmtQ"}

which decodes into:

    {
        "header": {
            "alg": "EdDSA",
            "kid": "did:key:z6MkrjypkHvMnBHUAJ9zp2qMPMyorjXqLcBMzG7bEXaangHz#z6MkrjypkHvMnBHUAJ9zp2qMPMyorjXqLcBMzG7bEXaangHz"
        },
        "payload": null,
        "signature": "Znk9Coho5DEnF7O6_pu61zxbSZqaC9tnWWkxfn3RQjK6U8V3nMInMixTTN9kJZJW25TscTFpcPQ_RXwDu1TIAQ"
    }

Verify via:

    echo '{"fancy":"stuff","proofs":["eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3JqeXBrSHZNbkJIVUFKOXpwMnFNUE15b3JqWHFMY0JNekc3YkVYYWFuZ0h6I3o2TWtyanlwa0h2TW5CSFVBSjl6cDJxTVBNeW9yalhxTGNCTXpHN2JFWGFhbmdIeiJ9..Znk9Coho5DEnF7O6_pu61zxbSZqaC9tnWWkxfn3RQjK6U8V3nMInMixTTN9kJZJW25TscTFpcPQ_RXwDu1TIAQ"],"selfHash":"En3kmljhbgxaPq-PW7nN3WlMGDjebVDL92uuAIxlmmtQ"}' | did-webplus vjson verify

Note that it's possible to create multiple wallets, `did:webplus` DIDs, and private keys for use with `did:key` using the various commandline arguments of `did-webplus`.  The default values for these arguments have been set up for convenience to use the uniquely determinable thing (e.g. wallet, DID) if there is exactly one, otherwise require more specific commandline arguments to specify which one to use.
