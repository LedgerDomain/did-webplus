# did-webplus

The `did:web` method makes straightforward use of familiar tools across a wide range of use cases. However, heavily regulated ecosystems such as the pharmaceutical supply chain demand additional guarantees of immutability and auditability, including seamless key rotation and a key usage history. `did:webplus` is a proposed fit-for-purpose DID method for use within the pharma supply chain credentialing community, with an eye towards releasing it into the wild for those communities that are similarly situated.

The [`did:webplus` specification](https://ledgerdomain.github.io/did-webplus-spec) gives all details on all components of `did:webplus`.

Here are the two "deep dive" presentations given at the DIF DID Methods Workgroup for `did:webplus`:
-   [Deep Dive 1](https://us02web.zoom.us/rec/share/aF-Oyy6vsSHTQVotgcMMpdxAMo_I0e3PyvFHl5Wrqy3PbLMsl283eXGb2OBGV0Dr.-f9s4l5thUU_4JpS) with [slides](https://docs.google.com/presentation/d/1fZDE-yJadk5NDwWYm3BDTIt0FvePeqjUl4Lrg0AaCNI/edit?usp=sharing).
-   [Deep Dive 2](https://us02web.zoom.us/rec/share/6yRpfB0ZND2JdmmYr6oQz8kYfFturosnG5ohQKxLNS4UXy80VyLuerzeNppo2XQ-.E74fBnNUdLYo1HFM) with [slides](https://docs.google.com/presentation/d/1sjsU9l-_0JJ9mY9aiUIUpzc5Ce8UTSt4SNXPTnPBmgM/edit?usp=sharing).

## Docker Images

-   [ghcr.io/ledgerdomain/did-webplus-cli] -- CLI tool for client-side operations (e.g. DID resolution, DID creation, etc).  Source and readme: [did-webplus-cli](did-webplus/cli)
-   [ghcr.io/ledgerdomain/did-webplus-urd] -- Universal Resolver Driver (URD) service.  Source and readme: [did-webplus-urd](did-webplus/urd)
-   [ghcr.io/ledgerdomain/did-webplus-vdg] -- Verifiable Data Gateway (VDG) service.  Source and readme: [did-webplus-vdg](did-webplus/vdg)
-   [ghcr.io/ledgerdomain/did-webplus-vdr] -- Verifiable Data Registry (VDR) service.  Source and readme: [did-webplus-vdr](did-webplus/vdr)

## Quick Overview

Component documentation:
-   [`did-webplus` CLI tool (reference implementation for client-side operations)](did-webplus/cli/README.md)
-   [`did:webplus` Verifiable Data Registry (VDR) service (reference implementation)](did-webplus/vdr/README.md)
-   [`did:webplus` Verifiable Data Gateway (VDG) service (reference implementation)](did-webplus/vdg/README.md)

## Examples

-   [Creating and Updating a DID](doc/example-creating-and-updating-a-did.md)
-   [DID Microledger](doc/example-did-microledger.md)
-   [Hash Function Selection](doc/example-hash-function-selection.md)
-   [Signature Generation With Witness](doc/example-signature-generation-with-witness.md)

To run the data model tests, which include printouts demonstrating various features and data structures, run

    cargo test -p did-webplus-core --all-features -- --nocapture

The full suite of unit and integration tests for the whole codebase can be run via

    SQLX_OFFLINE=true cargo test --workspace --all-features

Some of the log output will be error messages that are expected during the course of negative tests.

## License

[MIT](LICENSE)
