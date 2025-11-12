use crate::{Error, Result};
use std::{collections::HashMap, sync::Arc};

/// A data structure that contains a mapping of hostnames to HTTP schemes.  This is used to
/// override the default did:webplus resolution rules, which specify that localhost uses the "http"
/// scheme, and everything else uses the "https" scheme.  This data structure is used to determine
/// the HTTP scheme to use for a given hostname.
#[derive(Clone, Debug, Default)]
pub struct HTTPSchemeOverride(Arc<HashMap<String, &'static str>>);

impl HTTPSchemeOverride {
    /// Create a new `HTTPSchemeOverride` data structure with no overrides.
    pub fn new() -> Self {
        Self::default()
    }
    /// Builder-style method to add an override for the given hostname.  If the hostname already has an
    /// override, and it is the same as the given scheme, no error is returned.  If the hostname already
    /// has an override, and it is different from the given scheme, an error is returned.
    pub fn with_override(mut self, hostname: String, scheme: &str) -> Result<Self> {
        tracing::trace!(?hostname, ?scheme, "HTTPSchemeOverride::with_override");

        self.add_override(hostname, scheme)?;
        Ok(self)
    }
    pub fn add_override(&mut self, hostname: String, scheme: &str) -> Result<()> {
        tracing::trace!(
            ?hostname,
            ?scheme,
            "HTTPSchemeOverride::add_override: adding override"
        );

        let scheme = Self::parse_scheme_static_str(scheme)?;
        if let Some(&existing_scheme) = self.0.get(&hostname) {
            if existing_scheme == scheme {
                // No change, so no error.
                return Ok(());
            } else {
                return Err(Error::Malformed(
                    format!(
                        "Duplicated hostname ({:?}) with conflicting scheme",
                        hostname
                    )
                    .into(),
                ));
            }
        }

        // This will not clone if this Arc only has one reference, and will clone otherwise.
        let m = Arc::make_mut(&mut self.0);
        m.insert(hostname, scheme);

        Ok(())
    }
    /// Parse a comma-separated list of `hostname=scheme` pairs into a `HTTPSchemeOverride` data structure.
    pub fn parse_from_comma_separated_pairs(s: &str) -> Result<Self> {
        tracing::trace!(
            ?s,
            "HTTPSchemeOverride::parse_from_comma_separated_pairs: parsing"
        );

        // Trim whitespace before processing.
        let s = s.trim();

        let mut m = HashMap::new();
        if s.is_empty() {
            // Empty string means no overrides.
            return Ok(Self(Arc::new(m)));
        }

        for pair in s.split(',') {
            if let Some((hostname, scheme)) = pair.split_once('=') {
                // TODO: Validate that hostname is valid.
                // This ridiculous looking match is to obtain a &'static str from &str
                // that can have one of two known values.
                let http_scheme = match scheme {
                    "http" => "http",
                    "https" => "https",
                    _ => {
                        return Err(Error::Malformed(
                            format!(
                                "Invalid HTTP scheme ({:?}); expected \"http\" or \"https\"",
                                scheme
                            )
                            .into(),
                        ));
                    }
                };
                if let Some(&existing_http_scheme) = m.get(hostname) {
                    if existing_http_scheme != http_scheme {
                        return Err(Error::Malformed(
                            format!("Repeated hostname ({:?}) with conflicting scheme", hostname)
                                .into(),
                        ));
                    }
                }
                tracing::trace!(
                    ?hostname,
                    ?http_scheme,
                    "HTTPSchemeOverride::parse_from_comma_separated_pairs: inserting"
                );
                m.insert(hostname.to_string(), http_scheme);
            } else {
                tracing::error!(
                    ?pair,
                    "HTTPSchemeOverride::parse_from_comma_separated_pairs: malformed hostname=scheme pair: {}",
                    pair
                );
                return Err(Error::Malformed(
                    format!("Malformed hostname=scheme pair: {}", pair).into(),
                ));
            }
        }

        Ok(Self(Arc::new(m)))
    }
    /// The default did:webplus resolution rules specify that localhost uses the "http" scheme,
    /// and everything else uses the "https" scheme.  However, these mappings are overridden by
    /// this data structure, and the mapping for the given hostname is returned.  Note that
    /// "host" means hostname with optional port number (e.g. "fancy.com" or "localhost:8080").
    pub fn determine_http_scheme_for_host(&self, host: &str) -> Result<&'static str> {
        tracing::trace!(?host, "HTTPSchemeOverride::determine_http_scheme_for_host");

        let (hostname, _port_o) = Self::parse_hostname_and_port_o(host)?;
        match self.0.get(hostname) {
            // Override was specified, so use it.
            Some(&scheme) => {
                tracing::debug!(
                    "HTTPSchemeOverride::determine_http_scheme_for_host; self: {:?}; host: {}; overriding with scheme {}",
                    self,
                    host,
                    scheme
                );
                Ok(scheme)
            }
            // No override, so use the default did:webplus resolution rules.
            None => Self::default_http_scheme_for_host(hostname),
        }
    }
    /// Does the same thing as determine_http_scheme_for_hostname, except operates on Option<&Self>
    /// where None means "no override".  Note that "host" means hostname with optional port number
    /// (e.g. "fancy.com" or "localhost:8080").
    pub fn determine_http_scheme_for_host_from(
        http_scheme_override_o: Option<&Self>,
        host: &str,
    ) -> Result<&'static str> {
        tracing::trace!(
            ?http_scheme_override_o,
            ?host,
            "HTTPSchemeOverride::determine_http_scheme_for_host_from"
        );

        if let Some(http_scheme_override) = http_scheme_override_o {
            http_scheme_override.determine_http_scheme_for_host(host)
        } else {
            Self::default_http_scheme_for_host(host)
        }
    }
    /// Gives the default scheme determination rules for did:webplus -- if the hostname is "localhost",
    /// then the scheme is "http", and otherwise is "https".  Note that "host" means hostname with
    /// optional port number (e.g. "fancy.com" or "localhost:8080").
    pub fn default_http_scheme_for_host(host: &str) -> Result<&'static str> {
        let (hostname, _port_o) = Self::parse_hostname_and_port_o(host)?;
        if hostname == "localhost" {
            tracing::trace!(
                "HTTPSchemeOverride::default_http_scheme_for_host; host: {}; returning \"http\"",
                host
            );
            Ok("http")
        } else {
            tracing::trace!(
                "HTTPSchemeOverride::default_http_scheme_for_host; host: {}; returning \"https\"",
                host
            );
            Ok("https")
        }
    }
    fn parse_scheme_static_str(scheme: &str) -> Result<&'static str> {
        match scheme {
            "http" => Ok("http"),
            "https" => Ok("https"),
            _ => Err(Error::Malformed(
                format!(
                    "Invalid HTTP scheme ({:?}); expected \"http\" or \"https\"",
                    scheme
                )
                .into(),
            )),
        }
    }
    fn parse_hostname_and_port_o(host: &str) -> Result<(&str, Option<u16>)> {
        match host.split_once(':') {
            Some((hostname, port_str)) => {
                let port = port_str.parse::<u16>().map_err(|_| {
                    Error::Malformed(format!("Invalid port number: {}", port_str).into())
                })?;
                Ok((hostname, Some(port)))
            }
            None => Ok((host, None)),
        }
    }
}
