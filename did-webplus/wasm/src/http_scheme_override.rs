use crate::{Result, into_js_value};
use wasm_bindgen::prelude::wasm_bindgen;

/// HTTPSchemeOverride is a data structure that contains a mapping of hostnames to HTTP schemes,
/// used to override the default did:webplus resolution rules, which specify that localhost uses the "http"
/// scheme, and everything else uses the "https" scheme.  This is primarily used for testing and development.
#[wasm_bindgen]
#[derive(Clone)]
pub struct HTTPSchemeOverride(did_webplus_core::HTTPSchemeOverride);

#[wasm_bindgen]
impl HTTPSchemeOverride {
    /// Creates a new HTTPSchemeOverride with no overrides.
    pub fn new() -> Self {
        Self(did_webplus_core::HTTPSchemeOverride::new())
    }
    /// Parses a comma-separated list of `hostname=scheme` pairs into a HTTPSchemeOverride.
    pub fn parse_from_comma_separated_pairs(s: String) -> Result<Self> {
        let http_scheme_override =
            did_webplus_core::HTTPSchemeOverride::parse_from_comma_separated_pairs(s.as_str())
                .map_err(into_js_value)?;
        Ok(Self(http_scheme_override))
    }
    /// Adds an override for the given hostname and scheme.
    pub fn add_override(&mut self, hostname: String, scheme: String) -> Result<()> {
        self.0
            .add_override(hostname, scheme.as_str())
            .map_err(into_js_value)?;
        Ok(())
    }
    /// Determines the HTTP scheme for the given hostname.
    pub fn determine_http_scheme_for_hostname(&self, hostname: String) -> Result<String> {
        Ok(self
            .0
            .determine_http_scheme_for_host(hostname.as_str())
            .map_err(into_js_value)?
            .to_string())
    }
}

impl std::ops::Deref for HTTPSchemeOverride {
    type Target = did_webplus_core::HTTPSchemeOverride;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<did_webplus_core::HTTPSchemeOverride> for HTTPSchemeOverride {
    fn from(http_scheme_override: did_webplus_core::HTTPSchemeOverride) -> Self {
        Self(http_scheme_override)
    }
}

impl From<HTTPSchemeOverride> for did_webplus_core::HTTPSchemeOverride {
    fn from(http_scheme_override: HTTPSchemeOverride) -> Self {
        http_scheme_override.0
    }
}
