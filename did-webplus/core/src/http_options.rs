use crate::{HTTPHeadersFor, HTTPSchemeOverride};

#[derive(Clone, Debug, Default)]
pub struct HTTPOptions {
    pub http_headers_for: HTTPHeadersFor,
    pub http_scheme_override: HTTPSchemeOverride,
}
