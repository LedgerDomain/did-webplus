# did-webplus-wasm

WebAssembly SDK for did-webplus, including a JS/TS package.

## Necessary Toolchain

Note that you may need to install a few things:

-   The wasm32 Rust toolchain -- needed to build:

        rustup target add wasm32-unknown-unknown

-   The `wasm-pack` tool -- needed to create the JS/TS package:

        cargo install wasm-pack

-   NodeJS -- needed to run tests.  I installed the LTS (Long-Term Support) v18.19.1 from Ubuntu 24.

## Running Tests

Before running tests, the did-webplus VDR and VDG must be running.

### Build and Run the Test VDR and VDG

Everything needed is provided by `docker-compose.yml` and can be built, spun up, down, etc all via `make` commands.  Note that this particular docker configuration is NOT a production configuration!  See [this documentation](../vdr) for official VDR documentation.

In order for the `docker-compose.yml` configuration to work, it's necessary to ensure the following lines exist in the `/etc/hosts` file (this defines which hostnames get redirected where, and gives a way to redirect a named domain to localhost):

    # Used for did:webplus testing and development
    127.0.0.1  vdr.did-webplus-wasm.test
    127.0.0.1  vdg.did-webplus-wasm.test

You can verify this works via

    ping -c 1 -w 1 vdr.did-webplus-wasm.test && ping -c 1 -w 1 vdg.did-webplus-wasm.test

Now for the docker portion.  To build, run, and view logs for all the necessary docker services, from this directory (the did-webplus-wasm crate directory, which is `did-webplus/did-webplus/wasm`) run:

    make build && make run && make logs-all

You should see the log output of the VDR under `vdr.did-webplus-wasm.test_1` and the VDG under `vdg.did-webplus-wasm.test_1`.

### Running Tests in `node.js`

TEMPORARY NOTE: This is not expected to work at the moment.

Note that the test VDR and VDG MUST be running while running these tests.  See above for instructions.  From this directory (the did-webplus-wasm crate directory, which is `did-webplus/did-webplus/wasm`), run

    wasm-pack test --node # DON'T RUN THESE TESTS -- temporarily out of service.

### Running Tests in Browser (Headless Mode)

Note that the test VDR and VDG MUST be running in order for these tests to work.  See above for instructions.  From this directory (the did-webplus-wasm crate directory, which is `did-webplus/did-webplus/wasm`), run one of the following:

    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --chrome --headless --all-features
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --firefox --headless --all-features
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --safari --headless --all-features

You can even combine them if you have multiple browsers, e.g.

    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --chrome --firefox --safari --headless --all-features

### Running Tests in Browser (Headful Mode)

Note that the test VDR and VDG MUST be running in order for these tests to work.  See above for instructions.  From this directory (the did-webplus-wasm crate directory, which is `did-webplus/did-webplus/wasm`), run one of the following:

    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --chrome --all-features
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --firefox --all-features
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --safari --all-features

It will print a URL to open in your browser, and once open, the tests will run there.

## Notes on Logging

When using the SDK or running the tests in the browser, logging messages will be recorded in the usual place (see developer console) and are mapped from the `log`/`tracing` crate macros to browser console events in the following way:
| ----- | ------- |
| Rust  | Browser |
| ----- | ------- |
| error | error   |
| warn  | warn    |
| info  | info    |
| debug | log     |
| trace | debug   |

When running the tests in headless browser mode, only the Rust debug level messages will be sent to stdout.  The `RUST_LOG` env var doesn't affect this (it applies to the wasm-pack process that runs the tests, but not the tests themselves).  TODO: Fix this deficiency using the `wasm-tracing` crate (see did-webplus-software-wallet-indexeddb crate).

It appears that no logging is sent to stdout when the tests are run within node.js.  TODO: Fix this deficiency.

## Running Example

### Build and Run the Example Web Page

Note that the test VDR and VDG MUST be running in order for this example to work.  See above for instructions.  From this directory (the did-webplus-wasm crate directory, which is `did-webplus/did-webplus/wasm`), ensure the (release build of the) wasm package has been built:

    wasm-pack build --target web --all-features

Because this involves a size-optimization pass, this may take a few minutes to complete (during development, use `wasm-pack build --target web --all-features --debug` instead, which should complete quickly).  This should populate the `pkg` directory with various files, including:

    did_webplus_wasm_bg.wasm
    did_webplus_wasm_bg.wasm.d.ts
    did_webplus_wasm.d.ts
    did_webplus_wasm.js
    .gitignore
    package.json
    README.md

Then run a local web server to serve the example web page (`index.html`), e.g.

    python3 -m http.server 3000

and then load `http://localhost:3000` in your web browser.  This demo is intentionally **static** (no Vite/bundler) and is meant to be a simple but usable, professional-ish UI for exercising the WASM SDK.

#### Demo behavior

- **On page load**:
  - Initializes the WASM module.
  - Creates an IndexedDB-backed wallet.
  - Creates a DID resolver (thin resolver against the local dev VDG).
  - Nothing else is done automatically.

- **Global HTTP settings**:
  - The demo has a single global `HTTPOptions` configuration (scheme overrides + per-host headers) that applies to DID resolution and all wallet HTTP operations. This avoids needing to configure HTTP options per call.

- **User-driven actions**:
  - Wallet DID operations: create DID (with user-specified VDR create endpoint), update DID, deactivate DID (with irreversible confirmation modal).
  - Select the “active DID” used for update/deactivate and for all signing operations.
  - Create/clear a `WalletBasedSigner` used for signing, automatically cleared when active DID changes or when update/deactivate is performed.
  - Sign/issue: JWT, VC (JWT/LDP), VP (JWT/LDP). Signed artifacts are displayed with a Copy button.
  - Verify: JWT, VC (JWT/LDP), VP (JWT/LDP) with a simple tri-state result (not checked / valid / invalid).
  - Resolve DID: resolve arbitrary DID queries and show the resolved DID document (JCS) with Copy.
