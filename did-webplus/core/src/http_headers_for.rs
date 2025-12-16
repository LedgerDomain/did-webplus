use crate::{Error, Result};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HTTPHeader {
    pub name: String,
    pub value: String,
}

impl TryFrom<&str> for HTTPHeader {
    type Error = Error;
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        let (name, value) = s.split_once('=').ok_or(Error::Malformed(
            format!("Invalid HTTP header: {} -- expected name=value", s).into(),
        ))?;
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(Error::Malformed(
                format!(
                    "Invalid HTTP header: {} -- expected name=value with non-empty name",
                    s
                )
                .into(),
            ));
        }
        Ok(Self {
            name: name.to_string(),
            value: value.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct HTTPHeadersFor(Arc<HashMap<String, Vec<HTTPHeader>>>);

impl HTTPHeadersFor {
    pub fn new() -> Self {
        Self(Arc::new(HashMap::new()))
    }
    pub fn parse_from_semicolon_separated_pairs(s: &str) -> Result<Self> {
        Self::try_from(s)
    }
    pub fn add_header(&mut self, hostname: String, header: HTTPHeader) {
        // This will not clone if this Arc only has one reference, and will clone otherwise.
        let m = Arc::make_mut(&mut self.0);
        m.entry(hostname).or_insert_with(Vec::new).push(HTTPHeader {
            name: header.name,
            value: header.value,
        });
    }
    /// Returns the HTTP headers for the given hostname, or None if no headers are specified for the hostname.
    pub fn http_headers_for_hostname(&self, hostname: &str) -> Option<&[HTTPHeader]> {
        self.0.get(hostname).map(|headers| headers.as_slice())
    }
}

impl TryFrom<&str> for HTTPHeadersFor {
    type Error = Error;
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        let mut http_header_vm = HashMap::new();
        for hostname_and_http_header_strs in s.split(';') {
            if hostname_and_http_header_strs.is_empty() {
                continue;
            }
            let (hostname, http_header_strs) = hostname_and_http_header_strs
                .split_once('=')
                .ok_or(Error::Malformed(
                    format!(
                        "Invalid hostname and headers pair: {}",
                        hostname_and_http_header_strs
                    )
                    .into(),
                ))?;
            let http_header_v = http_header_strs
                .split(',')
                .map(|http_header_str| HTTPHeader::try_from(http_header_str))
                .collect::<Result<Vec<HTTPHeader>>>()?;
            http_header_vm.insert(hostname.to_string(), http_header_v);
        }
        Ok(Self(Arc::new(http_header_vm)))
    }
}
