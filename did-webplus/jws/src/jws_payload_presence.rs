#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "wasm-bindgen", wasm_bindgen::prelude::wasm_bindgen)]
pub enum JWSPayloadPresence {
    /// The payload is included within the JWS.
    Attached,
    /// The payload is not included within the JWS.
    Detached,
}
