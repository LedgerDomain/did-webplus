use crate::{parse_did_query_params, Error};

#[derive(Debug)]
pub struct DIDWebplusURIComponents<'a> {
    pub hostname: &'a str,
    pub port_o: Option<u16>,
    pub path_o: Option<&'a str>,
    pub root_self_hash: &'a mbx::MBHashStr,
    pub query_self_hash_o: Option<&'a mbx::MBHashStr>,
    pub query_version_id_o: Option<u32>,
    /// This is the fragment with the leading '#' char, if present.
    pub relative_resource_o: Option<&'a str>,
    pub fragment_o: Option<&'a str>,
}

impl<'a> DIDWebplusURIComponents<'a> {
    pub fn has_query(&self) -> bool {
        self.query_self_hash_o.is_some() || self.query_version_id_o.is_some()
    }
    pub fn has_fragment(&self) -> bool {
        self.fragment_o.is_some()
    }
}

impl<'a> std::fmt::Display for DIDWebplusURIComponents<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:webplus:{}", self.hostname)?;
        if let Some(port) = self.port_o {
            write!(f, "%3A{}", port)?;
        }
        if let Some(path) = self.path_o {
            write!(f, ":{}", path)?;
        }
        write!(f, ":{}", self.root_self_hash)?;
        if self.has_query() {
            write!(f, "?")?;
        }
        let mut query_printed = false;
        if let Some(query_self_hash) = self.query_self_hash_o {
            write!(f, "selfHash={}", query_self_hash)?;
            query_printed = true;
        }
        if let Some(query_version_id) = self.query_version_id_o {
            if query_printed {
                write!(f, "&")?;
            }
            write!(f, "versionId={}", query_version_id)?;
        }
        if let Some(fragment) = self.fragment_o {
            write!(f, "#{}", fragment)?;
        }
        Ok(())
    }
}

// TODO: Consider making a version of this that assumes that checks the constraints in debug_assert
// but otherwise assumes that the constraints are already satisfied, so it's faster to parse.
impl<'a> TryFrom<&'a str> for DIDWebplusURIComponents<'a> {
    type Error = Error;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if !s.starts_with("did:webplus:") {
            return Err(Error::Malformed(
                "did:webplus URI is expected to start with 'did:webplus:'",
            ));
        }
        // Get rid of the "did:webplus:" prefix.
        let s = s.strip_prefix("did:webplus:").unwrap();

        let (hostname_and_maybe_port, remainder) = s.split_once(':').ok_or(Error::Malformed(
            "did:webplus URI is expected to have a third ':' after the hostname",
        ))?;
        let (hostname, port_o) = if let Some((hostname, after_percent_str)) =
            hostname_and_maybe_port.split_once('%')
        {
            if !after_percent_str.starts_with("3A") {
                return Err(Error::Malformed("did:webplus URI may only have an embedded %3A (the percent-encoding of ':'), but it had some other percent-encoded char"));
            }
            let port_str = after_percent_str.strip_prefix("3A").unwrap();
            let port: u16 = port_str
                .parse()
                .map_err(|_| Error::Malformed("did:webplus URI port must be a valid integer"))?;
            (hostname, Some(port))
        } else {
            (hostname_and_maybe_port, None)
        };
        // TODO: Validation on hostname

        let (uri_path, query_o, relative_resource_o, fragment_o) =
            if let Some((uri_path, query_and_maybe_fragment)) = remainder.split_once('?') {
                if let Some((query, fragment)) = query_and_maybe_fragment.split_once('#') {
                    let relative_resource = query_and_maybe_fragment
                        .split_at(query_and_maybe_fragment.find('#').unwrap())
                        .1;
                    (
                        uri_path,
                        Some(query),
                        Some(relative_resource),
                        Some(fragment),
                    )
                } else {
                    (uri_path, Some(query_and_maybe_fragment), None, None)
                }
            } else if let Some((uri_path, fragment)) = remainder.split_once('#') {
                let relative_resource = remainder.split_at(remainder.find('#').unwrap()).1;
                (uri_path, None, Some(relative_resource), Some(fragment))
            } else {
                (remainder, None, None, None)
            };
        // TODO: Validation on path, query_o, and fragment_o

        // TODO: Stronger validation
        if uri_path.contains('/') || uri_path.contains('%') {
            return Err(Error::Malformed(
                "did:webplus URI path must not contain '/' or '%'",
            ));
        }

        // Split the URI path into the did:webplus path and root self-hash parts.
        let (path_o, root_self_hash_str) = if let Some((path, root_self_hash_str)) =
            uri_path.rsplit_once(':')
        {
            // TODO: More path validation.
            for path_component in path.split(':') {
                if path_component.is_empty() {
                    return Err(Error::Malformed("did:webplus URI path must not have empty path components (i.e. two ':' chars in a row)"));
                }
            }
            (Some(path), root_self_hash_str)
        } else {
            (None, uri_path)
        };
        let root_self_hash = mbx::MBHashStr::new_ref(root_self_hash_str)?;

        // Parse the query portion.
        let (query_self_hash_o, query_version_id_o) = if let Some(query) = query_o {
            parse_did_query_params(query)?
        } else {
            (None, None)
        };

        Ok(Self {
            hostname,
            port_o,
            path_o,
            root_self_hash,
            query_self_hash_o,
            query_version_id_o,
            relative_resource_o,
            fragment_o,
        })
    }
}
