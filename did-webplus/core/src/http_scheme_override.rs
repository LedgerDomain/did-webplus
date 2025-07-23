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
        self.add_override(hostname, scheme)?;
        Ok(self)
    }
    pub fn add_override(&mut self, hostname: String, scheme: &str) -> Result<()> {
        let scheme = Self::parse_scheme_static_str(scheme)?;
        if let Some(&existing_scheme) = self.0.get(&hostname) {
            if existing_scheme == scheme {
                // No change, so no error.
                return Ok(());
            } else {
                return Err(Error::Malformed(
                    "Duplicated hostname with conflicting scheme",
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
                            "Invalid HTTP scheme; expected \"http\" or \"https\"",
                        ))
                    }
                };
                if let Some(&existing_http_scheme) = m.get(hostname) {
                    if existing_http_scheme != http_scheme {
                        return Err(Error::Malformed(
                            "Repeated hostname with conflicting scheme",
                        ));
                    }
                }
                m.insert(hostname.to_string(), http_scheme);
            } else {
                return Err(Error::Malformed("Malformed hostname=scheme pair"));
            }
        }

        Ok(Self(Arc::new(m)))
    }
    /// The default did:webplus resolution rules specify that localhost uses the "http" scheme,
    /// and everything else uses the "https" scheme.  However, these mappings are overridden by
    /// this data structure, and the mapping for the given hostname is returned.
    pub fn determine_http_scheme_for_hostname(&self, hostname: &str) -> &'static str {
        match self.0.get(hostname) {
            // Override was specified, so use it.
            Some(&scheme) => {
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    "HTTPSchemeOverride::determine_http_scheme_for_hostname; self: {:?}; hostname: {}; overriding with scheme {}",
                    self,
                    hostname,
                    scheme
                );
                scheme
            }
            // No override, so use the default did:webplus resolution rules.
            None => Self::default_http_scheme_for_hostname(hostname),
        }
    }
    /// Does the same thing as determine_http_scheme_for_hostname, except operates on Option<&Self>
    /// where None means "no override".
    pub fn determine_http_scheme_for_hostname_from(
        http_scheme_override_o: Option<&Self>,
        hostname: &str,
    ) -> &'static str {
        if let Some(http_scheme_override) = http_scheme_override_o {
            http_scheme_override.determine_http_scheme_for_hostname(hostname)
        } else {
            Self::default_http_scheme_for_hostname(hostname)
        }
    }
    /// Gives the default scheme determination rules for did:webplus -- if the hostname is "localhost",
    /// then the scheme is "http", and otherwise is "https".
    pub fn default_http_scheme_for_hostname(hostname: &str) -> &'static str {
        if hostname == "localhost" {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                "HTTPSchemeOverride::default_http_scheme_for_hostname; hostname: {}; returning \"http\"",
                hostname
            );
            "http"
        } else {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                "HTTPSchemeOverride::default_http_scheme_for_hostname; hostname: {}; returning \"https\"",
                hostname
            );
            "https"
        }
    }
    fn parse_scheme_static_str(scheme: &str) -> Result<&'static str> {
        match scheme {
            "http" => Ok("http"),
            "https" => Ok("https"),
            _ => Err(Error::Malformed(
                "Invalid HTTP scheme; expected \"http\" or \"https\"",
            )),
        }
    }
}
