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

### Running Tests in `node.js`

From this directory (the did-webplus-wasm crate directory), run

    wasm-pack test --node

TEMPORARY NOTE: This is not expected to work at the moment.

### Running Tests in Browser (Headless Mode)

From this directory (the did-webplus-wasm crate directory), run one of the following:

    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --chrome --headless --all-features
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --firefox --headless --all-features
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --safari --headless --all-features

You can even combine them if you have multiple browsers, e.g.

    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --chrome --firefox --safari --headless --all-features

### Running Tests in Browser (Headful Mode)

From this directory (the did-webplus-wasm crate directory), run one of the following:

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

### Build and Run the VDR

Build and install `did-webplus-vdr` binary:

    cd ../vdr
    cargo install --path . --features postgres --debug

The `--debug` flag is optional, but it is useful for development purposes in order to report bugs.  It is not needed for production.

Create a "home" directory for the VDR (for the configuration):

    cd ~
    mkdir -p did-webplus/vdr_12321
    cd did-webplus/vdr_12321

Create a `.env` file for the VDR with the following contents:

    export DID_WEBPLUS_VDR_DID_HOST=localhost
    export DID_WEBPLUS_VDR_DID_PORT=12321
    export DID_WEBPLUS_VDR_LISTEN_PORT=12321
    export DID_WEBPLUS_VDR_DATABASE_URL=postgres:///did_webplus_vdr_12321
    export DID_WEBPLUS_VDR_GATEWAY_HOSTS=localhost:23456
    export DID_WEBPLUS_VDR_LOG_FORMAT=pretty
    export DID_WEBPLUS_VDR_HTTP_SCHEME_OVERRIDE=

    export RUST_LOG=did_webplus=debug,tower_http::trace::on_response=info,debug

Make sure that the postgres database has been created:

    psql -c 'create database did_webplus_vdr_12321'

Run the VDR (make sure you're in the `did-webplus/vdr_12321` directory):

    did-webplus-vdr

### Build and Run the Example Web Page

Ensure the wasm package has been built:

    wasm-pack build --target web --all-features

This should populate the `pkg` directory with various files, including:

    did_webplus_wasm_bg.wasm
    did_webplus_wasm_bg.wasm.d.ts
    did_webplus_wasm.d.ts
    did_webplus_wasm.js
    .gitignore
    package.json
    README.md

Ensure that the VDR is running (see above).  Then run a local web server to serve the example web page (`index.html`), e.g.

    python3 -m http.server 3000

and then load `http://localhost:3000` in your web browser.  This is a very ugly -- but working -- example of some critical features of did-webplus running in a browser.

For now, the IndexedDB-backed wallet is demonstrated upon first load, and its results can be seen in the console log.  There should be corresponding VDR log messages (e.g. about DID creation).
