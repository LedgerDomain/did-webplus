use crate::{Result, into_js_value};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct HTTPHeadersFor(did_webplus_core::HTTPHeadersFor);

#[wasm_bindgen]
impl HTTPHeadersFor {
    pub fn new() -> Result<Self> {
        Ok(Self(did_webplus_core::HTTPHeadersFor::new()))
    }
    pub fn parse_from_semicolon_separated_pairs(s: String) -> Result<Self> {
        let http_headers_for =
            did_webplus_core::HTTPHeadersFor::parse_from_semicolon_separated_pairs(s.as_str())
                .map_err(into_js_value)?;
        Ok(Self(http_headers_for))
    }
    pub fn add_header(&mut self, hostname: String, header_name: String, header_value: String) {
        self.0.add_header(
            hostname,
            did_webplus_core::HTTPHeader {
                name: header_name,
                value: header_value,
            },
        );
    }
}

impl std::ops::Deref for HTTPHeadersFor {
    type Target = did_webplus_core::HTTPHeadersFor;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<did_webplus_core::HTTPHeadersFor> for HTTPHeadersFor {
    fn from(http_headers_for: did_webplus_core::HTTPHeadersFor) -> Self {
        Self(http_headers_for)
    }
}

impl From<HTTPHeadersFor> for did_webplus_core::HTTPHeadersFor {
    fn from(http_headers_for: HTTPHeadersFor) -> Self {
        http_headers_for.0
    }
}
