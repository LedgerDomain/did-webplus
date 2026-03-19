use crate::{HTTPHeadersFor, HTTPSchemeOverride};
use wasm_bindgen::prelude::wasm_bindgen;

/// HTTPOptions is a data structure that contains HTTP headers and a HTTP scheme override
/// for use in various HTTP clients (e.g. DID resolution, DID create/update/deactivate, etc.).
#[wasm_bindgen]
#[derive(Clone)]
pub struct HTTPOptions(did_webplus_core::HTTPOptions);

#[wasm_bindgen]
impl HTTPOptions {
    /// Creates a new HTTPOptions with no headers or overrides.
    pub fn new() -> Self {
        Self(did_webplus_core::HTTPOptions::default())
    }
    /// Sets the HTTP headers.
    pub fn set_http_headers_for(&mut self, http_headers_for: HTTPHeadersFor) {
        self.0.http_headers_for = http_headers_for.into();
    }
    /// Sets the HTTP scheme override.
    pub fn set_http_scheme_override(&mut self, http_scheme_override: HTTPSchemeOverride) {
        self.0.http_scheme_override = http_scheme_override.into();
    }
}

impl std::ops::Deref for HTTPOptions {
    type Target = did_webplus_core::HTTPOptions;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<did_webplus_core::HTTPOptions> for HTTPOptions {
    fn from(http_options: did_webplus_core::HTTPOptions) -> Self {
        Self(http_options)
    }
}

impl From<HTTPOptions> for did_webplus_core::HTTPOptions {
    fn from(http_options: HTTPOptions) -> Self {
        http_options.0
    }
}
