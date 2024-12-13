#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "wasm-bindgen", wasm_bindgen::prelude::wasm_bindgen)]
pub enum JWSPayloadEncoding {
    /// No encoding.
    None,
    /// This really means base64url-no-pad encoding.
    Base64,
}
