# `did:webplus` Universal Resolver Driver (URD)

This is a [Universal Resolver](https://github.com/decentralized-identity/universal-resolver/tree/main) driver for (`did:webplus`)[https://ledgerdomain.github.io/did-webplus-spec], meaning that a properly configured Universal Resolver will dispatch DID resolution requests that begin with `did:webplus:` to this service.  See https://dev.uniresolver.io/ for a DIF-hosted instance of the Universal Resolver that can be used for testing purposes.

## Download

The latest docker image for this service can be downloaded via:

    docker pull ghcr.io/ledgerdomain/did-webplus-urd

Or for a specific version X.Y.Z:

    docker pull ghcr.io/ledgerdomain/did-webplus-urd:vX.Y.Z

## Usage

### Configuring and Running the Service

The command

    docker run ghcr.io/ledgerdomain/did-webplus-urd --help

shows the help screen

    This is the universal resolver driver for `did:webplus`.  It runs an HTTP server that resolves DID queries, using the did:webplus ["Full" DID Resolver](https://ledgerdomain.github.io/did-webplus-spec/#full-did-resolver). Queries can include query parameters for resolving DID documents of specific versions or self-hash values

    Usage: did-webplus-urd [OPTIONS] --database-url <DATABASE_URL>

    Options:
      -d, --database-url <DATABASE_URL>
              The URL of the database to use.  Must start with "postgres://" or "sqlite://".  An in-memory SQLite database can be specified as "sqlite://:memory:".  The postgres backend is only available if the "postgres" feature was enabled when this binary was built.  The sqlite backend is only available if the "sqlite" feature was enabled when this binary was built [env: DID_WEBPLUS_URD_DATABASE_URL=]
          --vdg <HOST>
              The host (host means hostname and optional port number) of the VDG to use for fetching DID documents.  This is used so that this resolver can take part in the scope of agreement defined by the VDG.  Without using a VDG, a "Full" DID resolver has a scope of agreement that only contains itself [env: DID_WEBPLUS_URD_VDG=]
          --http-headers-for <http-headers-for>
              Optionally specify a semicolon-separated list of comma-separated list of `name=value` pairs defining the HTTP headers to use for each of the specified hosts [env: DID_WEBPLUS_URD_HTTP_HEADERS_FOR=] [default: ]
          --http-scheme-override <http-scheme-override>
              Optionally specify a comma-separated list of `hostname=scheme` pairs defining the scheme to use for each of the specified hosts.  The default did:webplus resolution rules specify that localhost uses the "http" scheme, and everything else uses the "https" scheme.  This argument can be used to override this behavior for specific hostnames.  Besides localhost, the "http" scheme should only be used for testing and development [env: DID_WEBPLUS_URD_HTTP_SCHEME_OVERRIDE=] [default: ]
          --listen-port <LISTEN_PORT>
              The port to listen on.  Defaults to 80 [env: DID_WEBPLUS_URD_LISTEN_PORT=] [default: 80]
          --log-format <FORMAT>
              Specify the format of the logs.  "compact" produces one line per log message, while "pretty" produces verbose multi-line messages.  "json" produces JSON-formatted log messages [env: DID_WEBPLUS_URD_LOG_FORMAT=] [default: compact] [possible values: compact, json, pretty]
      -h, --help
              Print help

It is recommended to configure the service using the env vars (listed in the help screen above) through whatever orchestration tool you use for running docker containers (e.g. docker-compose).  An example `docker-compose.yml` is provided to run a PostgreSQL-backed instance of the URD listening on `localhost:8086`.  This can be run via `docker compose up` -- press Ctrl+C to stop it.

It is recommended also to set the env var

    RUST_LOG=tower_http::trace=warn,info

or if `did:webplus`-specific debug logging is desired,

    RUST_LOG=did_webplus=debug,tower_http::trace=warn,info

### Resolving a DID

A `did:webplus` DID can be resolved via HTTP request to the URD.  For example, if the service is running locally via the provided `docker-compose.yml`, then

    curl http://localhost:8086/1.0/identifiers/did:webplus:ledgerdomain.github.io:did-webplus-spec:uFiANVlMledNFUBJNiZPuvfgzxvJlGGDBIpDFpM4DXW6Bow

should return

    {"assertionMethod":["#0"],"authentication":["#0"],"capabilityDelegation":["#0"],"capabilityInvocation":["#0"],"id":"did:webplus:ledgerdomain.github.io:did-webplus-spec:uFiANVlMledNFUBJNiZPuvfgzxvJlGGDBIpDFpM4DXW6Bow","keyAgreement":["#0"],"prevDIDDocumentSelfHash":"uFiAsMCOasGw6SDizP1hIvfCtwGKKNBpjU-SmTfIMi5Lc6A","proofs":["eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRnl3VGV6LWtxa1BmVkVvcG9RZzZvWkp4Z2xBc3Jua0ZaTjdRc3A0Vkw3TUEiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..D_OKeKACyD8aIVvgGpTCQ2HubK2eEWGBfb31n_JSZrw7SscmeY6JOHBj_5eVLZXwERxuoov2piT73BCC7oxwDQ"],"selfHash":"uFiBjPx5fQEzbfrZUlXA6K2oTS--9Kt1eLeWpwHBRsI521Q","updateRules":{"hashedKey":"uFiBiYhrMw5paP5p5XZBamwO3ewct7qogo6PmetBBbObfNg"},"validFrom":"2026-02-11T06:51:14.59Z","verificationMethod":[{"controller":"did:webplus:ledgerdomain.github.io:did-webplus-spec:uFiANVlMledNFUBJNiZPuvfgzxvJlGGDBIpDFpM4DXW6Bow","id":"did:webplus:ledgerdomain.github.io:did-webplus-spec:uFiANVlMledNFUBJNiZPuvfgzxvJlGGDBIpDFpM4DXW6Bow?selfHash=uFiBjPx5fQEzbfrZUlXA6K2oTS--9Kt1eLeWpwHBRsI521Q&versionId=2#0","publicKeyJwk":{"crv":"Ed25519","kid":"did:webplus:ledgerdomain.github.io:did-webplus-spec:uFiANVlMledNFUBJNiZPuvfgzxvJlGGDBIpDFpM4DXW6Bow?selfHash=uFiBjPx5fQEzbfrZUlXA6K2oTS--9Kt1eLeWpwHBRsI521Q&versionId=2#0","kty":"OKP","x":"u6vCiZ0mBc8A3-yd6I273zoV87YuBbgzeVZfXELlyKw"},"type":"JsonWebKey2020"}],"versionId":2}

Similarly,

    curl http://localhost:8086/1.0/identifiers/did:webplus:ledgerdomain.github.io:did-webplus-spec:uFiDBw4xANa8sR_Fd8-pv-X9A5XIJNS3tC_bRNB3HUYiKug

should return

    {"assertionMethod":[],"authentication":[],"capabilityDelegation":[],"capabilityInvocation":[],"id":"did:webplus:ledgerdomain.github.io:did-webplus-spec:uFiDBw4xANa8sR_Fd8-pv-X9A5XIJNS3tC_bRNB3HUYiKug","keyAgreement":[],"prevDIDDocumentSelfHash":"uFiCCY8US1SG4VLelUh4IXDZ8V8We1djyolblOJ675tQotg","proofs":["eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoidTdRRnRtNnFzUnNrNDdDYlhJWUhoLWttMmVncmJneWxLbWV5cTFuakVPS0tlWkEiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..HpjXgqWQj70j0VA8-godJfIdop4RsSqEQBUJieJi_MhFxgM_sIlX8Yj1Wf_kRHCWQC0Ps2HlZaKe2H5SuBGzAA"],"selfHash":"uFiB22brlXeP5TPc7qqOxeOJsxuixRv2jE9rmFCRLVBizHw","updateRules":{},"validFrom":"2026-02-11T06:49:42.596Z","verificationMethod":[],"versionId":2}
