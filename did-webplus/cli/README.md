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

## Running against the dockerized demo VDR and VDG services

After installing the native binary, follow instructions [here](../vdg) to spin up the dockerized demo VDR and VDG services.  Once they're up and running, the `did-webplus` CLI tool can be run against them by first setting certain environment variables to point to the dockerized services.

    export DID_WEBPLUS_VDG=dockerized.vdg.local:8086
    export DID_WEBPLUS_VDG=dockerized.vdr.local:8085
    export DID_WEBPLUS_HTTP_SCHEME_OVERRIDE=dockerized.vdr.local=http,dockerized.vdg.local=http

Once these are set, follow instructions below for how to run various commands.  Note that this will all be running purely locally, and no DID documents will be accessible from outside the local machine.

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

This command will create a new DID, along with an associated set of private keys, and publish the DID document to the VDR `http://dockerized.vdr.local` (the VDR service running in the docker-compose).

    did-webplus wallet did create

It will print the fully-qualified DID (which means the query parameters that specify the `selfHash` and `versionId` of the latest DID document are present), e.g.

    did:webplus:dockerized.vdr.local%3A8085:uHiAPukNGyeIoJnlwRBVbCTAQ-Bc_Hpo7lYyo-nuXoHXvHg?selfHash=uHiAPukNGyeIoJnlwRBVbCTAQ-Bc_Hpo7lYyo-nuXoHXvHg&versionId=0

The DID is the portion before the `?`:

    did:webplus:dockerized.vdr.local%3A8085:uHiAPukNGyeIoJnlwRBVbCTAQ-Bc_Hpo7lYyo-nuXoHXvHg

Note that the VDR host `dockerized.vdr.local:8085` is percent-encoded in the DID as `dockerized.vdr.local%3A8085`.

#### Wallet-based DID List

You can list the DIDs that the wallet controls:

    did-webplus wallet did list

E.g. output:

    ["did:webplus:dockerized.vdr.local%3A8085:uHiAPukNGyeIoJnlwRBVbCTAQ-Bc_Hpo7lYyo-nuXoHXvHg"]

#### Wallet-based DID Update

This command will update the DID by rotating all of its associated keys and publishing the DID document to the VDR (which is specified by the DID itself):

    did-webplus wallet did update

It will print the updated, fully-qualified DID; notice the versionId value:

    did:webplus:dockerized.vdr.local%3A8085:uHiAPukNGyeIoJnlwRBVbCTAQ-Bc_Hpo7lYyo-nuXoHXvHg?selfHash=uHiCYGj_YQVt-SpDDdehBeUnj4SSDCxC-XPRrrpezlnxdSQ&versionId=1

#### Wallet-based DID Sign JWS

Now produce a JWS that is signed by the DID:

    echo '{"blah": 123}' | did-webplus wallet did sign jws --key-purpose assertion-method

This will output the JWS:

    eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYnBsdXM6ZG9ja2VyaXplZC52ZHIubG9jYWwlM0E4MDg1OnVIaUFQdWtOR3llSW9Kbmx3UkJWYkNUQVEtQmNfSHBvN2xZeW8tbnVYb0hYdkhnP3NlbGZIYXNoPXVIaUNZR2pfWVFWdC1TcEREZGVoQmVVbmo0U1NEQ3hDLVhQUnJycGV6bG54ZFNRJnZlcnNpb25JZD0xIzEifQ.eyJibGFoIjogMTIzfQo.SNx7TEpJsYR0RkiE8oMB6Mn5KtcpVxCOQNUnd5DqMn8o6WlkNeREtKzUx8KKRdGX80Col3qPJdRSns0H0hf0Bg

which decodes as:

    {
        "header": {
            "alg": "Ed25519",
            "kid": "did:webplus:dockerized.vdr.local%3A8085:uHiAPukNGyeIoJnlwRBVbCTAQ-Bc_Hpo7lYyo-nuXoHXvHg?selfHash=uHiCYGj_YQVt-SpDDdehBeUnj4SSDCxC-XPRrrpezlnxdSQ&versionId=1#1"
        },
        "payload": {
            "blah": 123
        },
        "signature": "SNx7TEpJsYR0RkiE8oMB6Mn5KtcpVxCOQNUnd5DqMn8o6WlkNeREtKzUx8KKRdGX80Col3qPJdRSns0H0hf0Bg"
    }

#### Verify JWS

Notice how the fully-qualified DID is used in the `"kid"` field of the JWS header.  This is used in verifying the JWS:

    echo eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYnBsdXM6ZG9ja2VyaXplZC52ZHIubG9jYWwlM0E4MDg1OnVIaUFQdWtOR3llSW9Kbmx3UkJWYkNUQVEtQmNfSHBvN2xZeW8tbnVYb0hYdkhnP3NlbGZIYXNoPXVIaUNZR2pfWVFWdC1TcEREZGVoQmVVbmo0U1NEQ3hDLVhQUnJycGV6bG54ZFNRJnZlcnNpb25JZD0xIzEifQ.eyJibGFoIjogMTIzfQo.SNx7TEpJsYR0RkiE8oMB6Mn5KtcpVxCOQNUnd5DqMn8o6WlkNeREtKzUx8KKRdGX80Col3qPJdRSns0H0hf0Bg | did-webplus jws verify

If the JWS was successfully verified, it will print nothing and return with exit code 0 (success).  Otherwise the JWS failed verification and an error message will be printed and a nonzero exit code will be returned.

#### VJSON Self-Hash

Verifiable JSON (VJSON) will be detailed more later, but the TL;DR is that VJSON a self-hashed JSON blob that has 0 or more digital signatures in JWS form.  To create a VJSON with no signatures and only a self-hash, run:

    echo '{"some": [true, "fancy", "data"], "$id": "vjson:///"}' | did-webplus vjson self-hash

The output is the same JSON blob but self-hashed.  Note that this output is deterministic, unlike the above examples that use a randomly-generated private key.

    {"$id":"vjson:///uHiCD_PkZCu47kFpYaVM24wfbdJwpkd7qJNInnPPyKy2Kig","$schema":"vjson:///uHiAqyDN1_izR799JHTkUBDSKMy0-P0RK0Hegzoc4GqwDPg","selfHash":"uHiCD_PkZCu47kFpYaVM24wfbdJwpkd7qJNInnPPyKy2Kig","some":[true,"fancy","data"]}

#### VJSON Verify

This VJSON can be verified (note the necessary single quotes in the `echo` command):

    echo '{"$id":"vjson:///uHiCD_PkZCu47kFpYaVM24wfbdJwpkd7qJNInnPPyKy2Kig","$schema":"vjson:///uHiAqyDN1_izR799JHTkUBDSKMy0-P0RK0Hegzoc4GqwDPg","selfHash":"uHiCD_PkZCu47kFpYaVM24wfbdJwpkd7qJNInnPPyKy2Kig","some":[true,"fancy","data"]}' | did-webplus vjson verify

If verified, it will print the verified VJSON and return with exit code 0 (success).  If invalid, it will print an error message and return with nonzero exit code.

#### Wallet-based DID Sign VJSON

Signed VJSON can be produced either from an plain JSON blob or an existing VJSON blob.  Signatures, which are JWS with detached payload, will be appended into the "proofs" field (which will be an array of JWS strings).  Signatures exclude the "proofs" field when signing, and furthermore set the self-hash slot(s) to the appropriate placeholder value before signing, so that the self-hash can be computed after the "proofs" field is re-included with the newly created signature.  This is so multiple signatures that all sign the same payload can be included in the VJSON.

Using the same JSON blob as the previous example:

    echo '{"some": [true, "fancy", "data"], "$id": "vjson:///"}' | did-webplus wallet did sign vjson --key-purpose assertion-method

The output is the signed, self-hashed VJSON.

    {"$id":"vjson:///uHiCuwBDk_DLyfvc3nDUMr1-yRqZ3w6ebwbW8kdjvGPFCxQ","$schema":"vjson:///uHiAqyDN1_izR799JHTkUBDSKMy0-P0RK0Hegzoc4GqwDPg","proofs":["eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYnBsdXM6ZG9ja2VyaXplZC52ZHIubG9jYWwlM0E4MDg1OnVIaUFQdWtOR3llSW9Kbmx3UkJWYkNUQVEtQmNfSHBvN2xZeW8tbnVYb0hYdkhnP3NlbGZIYXNoPXVIaUNZR2pfWVFWdC1TcEREZGVoQmVVbmo0U1NEQ3hDLVhQUnJycGV6bG54ZFNRJnZlcnNpb25JZD0xIzEifQ..9r0_A263DDA7FNIbEBdEzk1wNZxm3ZGcate0sq1h3kcl4DTd_aS23_elziZ1KzyZwdquzVMna2x2MdSMun2YBw"],"selfHash":"uHiCuwBDk_DLyfvc3nDUMr1-yRqZ3w6ebwbW8kdjvGPFCxQ","some":[true,"fancy","data"]}

Note that the JWS in the proofs field decodes as

    {
        "header": {
            "alg": "Ed25519",
            "kid": "did:webplus:dockerized.vdr.local%3A8085:uHiAPukNGyeIoJnlwRBVbCTAQ-Bc_Hpo7lYyo-nuXoHXvHg?selfHash=uHiCYGj_YQVt-SpDDdehBeUnj4SSDCxC-XPRrrpezlnxdSQ&versionId=1#1"
        },
        "payload": null,
        "signature": "9r0_A263DDA7FNIbEBdEzk1wNZxm3ZGcate0sq1h3kcl4DTd_aS23_elziZ1KzyZwdquzVMna2x2MdSMun2YBw"
    }

That `"payload": null` indicates that the JWS has a detached payload which is derived from the VJSON.  This VJSON can be verified:

    echo '{"$id":"vjson:///uHiCuwBDk_DLyfvc3nDUMr1-yRqZ3w6ebwbW8kdjvGPFCxQ","$schema":"vjson:///uHiAqyDN1_izR799JHTkUBDSKMy0-P0RK0Hegzoc4GqwDPg","proofs":["eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYnBsdXM6ZG9ja2VyaXplZC52ZHIubG9jYWwlM0E4MDg1OnVIaUFQdWtOR3llSW9Kbmx3UkJWYkNUQVEtQmNfSHBvN2xZeW8tbnVYb0hYdkhnP3NlbGZIYXNoPXVIaUNZR2pfWVFWdC1TcEREZGVoQmVVbmo0U1NEQ3hDLVhQUnJycGV6bG54ZFNRJnZlcnNpb25JZD0xIzEifQ..9r0_A263DDA7FNIbEBdEzk1wNZxm3ZGcate0sq1h3kcl4DTd_aS23_elziZ1KzyZwdquzVMna2x2MdSMun2YBw"],"selfHash":"uHiCuwBDk_DLyfvc3nDUMr1-yRqZ3w6ebwbW8kdjvGPFCxQ","some":[true,"fancy","data"]}' | did-webplus vjson verify

Upon verification success, the VJSON blob will be printed and the process will return with exit code 0.

#### Wallet-based DID Sign VJSON (Append Another Signature)

This VJSON can be fed back in to add another signature.  Let's use a different key purpose so that it's a different signing key.

    echo '{"$id":"vjson:///EKNo4-U0r3ToVqk9kQofzQZZT21-F3Q7HmaAOFRQ5m0w","$schema":"vjson:///EnD4KcLMLmGSjEliVPgBdMsEC2B_brlSXPV2pu7W90Xc","proofs":["eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWJwbHVzOmZhbmN5Lm5ldDpFMl9kUjBmSVprT2Q0S3djeVJDdTJvSWZ0Y04zd0JDSm9Yd2xWdEg1VXc3RT9zZWxmSGFzaD1FMWI0UnZhRlFZazRBYjF1LWM5dHBUcElDWDF1ZjJZYlpkOUlrblBaMWF5dyZ2ZXJzaW9uSWQ9MSNETlJGWk03WEhfRHgwRFh0NTFqUmpoeHkyMGV6Y29PSTloRkhiZFp1bjV0OCJ9..K1v0p7f0UV9ktLO8UJ4h1cafILgZGS6t7KKZJWBqitsccM27KPvG-XG_iPwq-ArVijw4rxxnOoEHeaJwAWsnCA"],"selfHash":"EKNo4-U0r3ToVqk9kQofzQZZT21-F3Q7HmaAOFRQ5m0w","some":[true,"fancy","data"]}' | did-webplus wallet did sign vjson --key-purpose authentication

The output VJSON now has two elements in the "proofs" array:

    {"$id":"vjson:///uHiCxo_1ukEC79b6YVYTUECFvg5ga4j3hzsazvdMij9Q35g","$schema":"vjson:///uHiAqyDN1_izR799JHTkUBDSKMy0-P0RK0Hegzoc4GqwDPg","proofs":["eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYnBsdXM6ZG9ja2VyaXplZC52ZHIubG9jYWwlM0E4MDg1OnVIaUFQdWtOR3llSW9Kbmx3UkJWYkNUQVEtQmNfSHBvN2xZeW8tbnVYb0hYdkhnP3NlbGZIYXNoPXVIaUNZR2pfWVFWdC1TcEREZGVoQmVVbmo0U1NEQ3hDLVhQUnJycGV6bG54ZFNRJnZlcnNpb25JZD0xIzEifQ..9r0_A263DDA7FNIbEBdEzk1wNZxm3ZGcate0sq1h3kcl4DTd_aS23_elziZ1KzyZwdquzVMna2x2MdSMun2YBw","eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYnBsdXM6ZG9ja2VyaXplZC52ZHIubG9jYWwlM0E4MDg1OnVIaUFQdWtOR3llSW9Kbmx3UkJWYkNUQVEtQmNfSHBvN2xZeW8tbnVYb0hYdkhnP3NlbGZIYXNoPXVIaUNZR2pfWVFWdC1TcEREZGVoQmVVbmo0U1NEQ3hDLVhQUnJycGV6bG54ZFNRJnZlcnNpb25JZD0xIzAifQ..359zjS7wn2XFmDAQBCUIx2ete26MwSXvWbrkbKqyQ6yirWS6s6evrfTLc15T6JbTMV66QeY80PxgZyk3tRr8Aw"],"selfHash":"uHiCxo_1ukEC79b6YVYTUECFvg5ga4j3hzsazvdMij9Q35g","some":[true,"fancy","data"]}

The second JWS in the proofs field decodes as

    {
        "header": {
            "alg": "Ed25519",
            "kid": "did:webplus:dockerized.vdr.local%3A8085:uHiAPukNGyeIoJnlwRBVbCTAQ-Bc_Hpo7lYyo-nuXoHXvHg?selfHash=uHiCYGj_YQVt-SpDDdehBeUnj4SSDCxC-XPRrrpezlnxdSQ&versionId=1#0"
        },
        "payload": null,
        "signature": "359zjS7wn2XFmDAQBCUIx2ete26MwSXvWbrkbKqyQ6yirWS6s6evrfTLc15T6JbTMV66QeY80PxgZyk3tRr8Aw"
    }

#### VJSON Verify

To verify the VJSON:

    echo '{"$id":"vjson:///uHiCxo_1ukEC79b6YVYTUECFvg5ga4j3hzsazvdMij9Q35g","$schema":"vjson:///uHiAqyDN1_izR799JHTkUBDSKMy0-P0RK0Hegzoc4GqwDPg","proofs":["eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYnBsdXM6ZG9ja2VyaXplZC52ZHIubG9jYWwlM0E4MDg1OnVIaUFQdWtOR3llSW9Kbmx3UkJWYkNUQVEtQmNfSHBvN2xZeW8tbnVYb0hYdkhnP3NlbGZIYXNoPXVIaUNZR2pfWVFWdC1TcEREZGVoQmVVbmo0U1NEQ3hDLVhQUnJycGV6bG54ZFNRJnZlcnNpb25JZD0xIzEifQ..9r0_A263DDA7FNIbEBdEzk1wNZxm3ZGcate0sq1h3kcl4DTd_aS23_elziZ1KzyZwdquzVMna2x2MdSMun2YBw","eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOndlYnBsdXM6ZG9ja2VyaXplZC52ZHIubG9jYWwlM0E4MDg1OnVIaUFQdWtOR3llSW9Kbmx3UkJWYkNUQVEtQmNfSHBvN2xZeW8tbnVYb0hYdkhnP3NlbGZIYXNoPXVIaUNZR2pfWVFWdC1TcEREZGVoQmVVbmo0U1NEQ3hDLVhQUnJycGV6bG54ZFNRJnZlcnNpb25JZD0xIzAifQ..359zjS7wn2XFmDAQBCUIx2ete26MwSXvWbrkbKqyQ6yirWS6s6evrfTLc15T6JbTMV66QeY80PxgZyk3tRr8Aw"],"selfHash":"uHiCxo_1ukEC79b6YVYTUECFvg5ga4j3hzsazvdMij9Q35g","some":[true,"fancy","data"]}' | did-webplus vjson verify

Notice that the selfHash field has changed each time a proof was added.
-   With no `proofs` field, the `selfHash` field was `uHiCD_PkZCu47kFpYaVM24wfbdJwpkd7qJNInnPPyKy2Kig`.
-   With one element in `proofs`, the `selfHash` field was `uHiCuwBDk_DLyfvc3nDUMr1-yRqZ3w6ebwbW8kdjvGPFCxQ`.
-   With two elements in `proofs`, the `selfHash` field was `uHiCxo_1ukEC79b6YVYTUECFvg5ga4j3hzsazvdMij9Q35g`.

This is because the self-hash is computed over the whole VJSON, including the `proofs` field.

#### DID-Key Generate

Finally, using a `did:webplus` DID may require contact with the VDR and/or VDG, and for testing and development purposes, it's often useful to use a static DID method that doesn't require any service for DID resolution.  In particular, `did:key`.  To generate a private key for use with `did:key`, run:

    did-webplus did-key generate --key-type ed25519

This will print the `did:key` form of the corresponding public key, e.g.

    did:key:z6MkhikuRnfovBGisSrYh68kHy2HX17NV5SM1PWnk7xtXn43

#### DID-Key From-Private

If you need to print this public `did:key` again, run:

    did-webplus did-key from-private

and it will print the expected DID:

    did:key:z6MkhikuRnfovBGisSrYh68kHy2HX17NV5SM1PWnk7xtXn43

#### DID-Key Sign JWS

You can sign JWS and VJSON using `did:key`:

    echo '{"fancy": "stuff"}' | did-webplus did-key sign jws

Output, e.g.:

    eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOmtleTp6Nk1raGlrdVJuZm92Qkdpc1NyWWg2OGtIeTJIWDE3TlY1U00xUFduazd4dFhuNDMjejZNa2hpa3VSbmZvdkJHaXNTclloNjhrSHkySFgxN05WNVNNMVBXbms3eHRYbjQzIn0.eyJmYW5jeSI6ICJzdHVmZiJ9Cg.Src2dyt6SIesZUp4qfZ_wUADdGBDUH3bZamjiKgpr9oNGEdEF3XtADzgrZdSRboyoywAtAW4p2sj-MgFB6yWBg

which decodes into:

    {
        "header": {
            "alg": "Ed25519",
            "kid": "did:key:z6MkhikuRnfovBGisSrYh68kHy2HX17NV5SM1PWnk7xtXn43#z6MkhikuRnfovBGisSrYh68kHy2HX17NV5SM1PWnk7xtXn43"
        },
        "payload": {
            "fancy": "stuff"
        },
        "signature": "Src2dyt6SIesZUp4qfZ_wUADdGBDUH3bZamjiKgpr9oNGEdEF3XtADzgrZdSRboyoywAtAW4p2sj-MgFB6yWBg"
    }

Verify via:

    echo eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOmtleTp6Nk1raGlrdVJuZm92Qkdpc1NyWWg2OGtIeTJIWDE3TlY1U00xUFduazd4dFhuNDMjejZNa2hpa3VSbmZvdkJHaXNTclloNjhrSHkySFgxN05WNVNNMVBXbms3eHRYbjQzIn0.eyJmYW5jeSI6ICJzdHVmZiJ9Cg.Src2dyt6SIesZUp4qfZ_wUADdGBDUH3bZamjiKgpr9oNGEdEF3XtADzgrZdSRboyoywAtAW4p2sj-MgFB6yWBg | did-webplus jws verify

#### DID-Key Sign VJSON

Similarly,

    echo '{"fancy": "stuff", "$id":"vjson:///"}' | did-webplus did-key sign vjson

Output, e.g.:

    {"$id":"vjson:///uHiDnfDRmFXvmRfJWR7EkVrwJWVvJPCVyvOqyWGH_EdG2hA","$schema":"vjson:///uHiAqyDN1_izR799JHTkUBDSKMy0-P0RK0Hegzoc4GqwDPg","fancy":"stuff","proofs":["eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOmtleTp6Nk1raGlrdVJuZm92Qkdpc1NyWWg2OGtIeTJIWDE3TlY1U00xUFduazd4dFhuNDMjejZNa2hpa3VSbmZvdkJHaXNTclloNjhrSHkySFgxN05WNVNNMVBXbms3eHRYbjQzIn0..ipPx6m4Akc1jAgDWCS3u_PcPZ3XBztQl28DEj6t0pi-qUcEvonpudGEBzryKc1Ee_VyCO0olmRvcXtuzMkdKAQ"],"selfHash":"uHiDnfDRmFXvmRfJWR7EkVrwJWVvJPCVyvOqyWGH_EdG2hA"}

where the JWS decodes into:

    {
        "header": {
            "alg": "Ed25519",
            "kid": "did:key:z6MkhikuRnfovBGisSrYh68kHy2HX17NV5SM1PWnk7xtXn43#z6MkhikuRnfovBGisSrYh68kHy2HX17NV5SM1PWnk7xtXn43"
        },
        "payload": null,
        "signature": "ipPx6m4Akc1jAgDWCS3u_PcPZ3XBztQl28DEj6t0pi-qUcEvonpudGEBzryKc1Ee_VyCO0olmRvcXtuzMkdKAQ"
    }

Verify via:

    echo '{"$id":"vjson:///uHiDnfDRmFXvmRfJWR7EkVrwJWVvJPCVyvOqyWGH_EdG2hA","$schema":"vjson:///uHiAqyDN1_izR799JHTkUBDSKMy0-P0RK0Hegzoc4GqwDPg","fancy":"stuff","proofs":["eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiZGlkOmtleTp6Nk1raGlrdVJuZm92Qkdpc1NyWWg2OGtIeTJIWDE3TlY1U00xUFduazd4dFhuNDMjejZNa2hpa3VSbmZvdkJHaXNTclloNjhrSHkySFgxN05WNVNNMVBXbms3eHRYbjQzIn0..ipPx6m4Akc1jAgDWCS3u_PcPZ3XBztQl28DEj6t0pi-qUcEvonpudGEBzryKc1Ee_VyCO0olmRvcXtuzMkdKAQ"],"selfHash":"uHiDnfDRmFXvmRfJWR7EkVrwJWVvJPCVyvOqyWGH_EdG2hA"}' | did-webplus vjson verify

Note that it's possible to create multiple wallets, `did:webplus` DIDs, and private keys for use with `did:key` using the various commandline arguments of `did-webplus`.  The default values for these arguments have been set up for convenience to use the uniquely determinable thing (e.g. wallet, DID) if there is exactly one, otherwise require more specific commandline arguments to specify which one to use.
