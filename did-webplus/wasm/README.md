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

### Running Tests in Browser (Headless Mode)

From this directory (the did-webplus-wasm crate directory), run one of the following:

    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --headless --chrome
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --headless --firefox
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --headless --safari

You can even combine them if you have multiple browsers, e.g.

    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --headless --chrome --firefox --safari

### Running Tests in Browser (Headful Mode)

From this directory (the did-webplus-wasm crate directory), run one of the following:

    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --chrome
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --firefox
    WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --safari

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

When running the tests in headless browser mode, only the Rust debug level messages will be sent to stdout.  The `RUST_LOG` env var doesn't affect this (it applies to the wasm-pack process that runs the tests, but not the tests themselves).  TODO: Fix this deficiency (note that the `tracing-wasm` crate exists, but is out of date and seems to be unmaintained).

It appears that no logging is sent to stdout when the tests are run within node.js.  TODO: Fix this deficiency.

## Running Example

Ensure the wasm package, which appears as the `pkg` directory, has been built.  Then run a local web server, e.g.

    python3 -m http.server 3000

and then load http://localhost:3000 in your web browser.  This is a very ugly -- but working -- example of some critical features of did-webplus running in a browser.
