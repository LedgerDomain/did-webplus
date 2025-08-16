use crate::{into_js_value, Result};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct HTTPSchemeOverride(did_webplus_core::HTTPSchemeOverride);

#[wasm_bindgen]
impl HTTPSchemeOverride {
    pub fn new() -> Result<Self> {
        Ok(Self(did_webplus_core::HTTPSchemeOverride::new()))
    }
    pub fn parse_from_comma_separated_pairs(s: String) -> Result<Self> {
        let http_scheme_override =
            did_webplus_core::HTTPSchemeOverride::parse_from_comma_separated_pairs(s.as_str())
                .map_err(into_js_value)?;
        Ok(Self(http_scheme_override))
    }
    pub fn add_override(&mut self, hostname: String, scheme: String) -> Result<()> {
        self.0
            .add_override(hostname, scheme.as_str())
            .map_err(into_js_value)?;
        Ok(())
    }
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
