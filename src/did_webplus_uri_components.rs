use crate::{parse_did_query_params, Error};

#[derive(Debug)]
pub struct DIDWebplusURIComponents<'a> {
    pub host: &'a str,
    pub path_o: Option<&'a str>,
    pub root_self_hash: &'a selfhash::KERIHashStr,
    pub query_self_hash_o: Option<&'a selfhash::KERIHashStr>,
    pub query_version_id_o: Option<u32>,
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

        let (host, post_host_str) = s.split_once(':').ok_or(Error::Malformed(
            "did:webplus URI is expected to have a third ':' after the host",
        ))?;
        // TODO: Validation on host

        let (uri_path, query_o, fragment_o) =
            if let Some((uri_path, query_and_maybe_fragment)) = post_host_str.split_once('?') {
                if let Some((query, fragment)) = query_and_maybe_fragment.split_once('#') {
                    (uri_path, Some(query), Some(fragment))
                } else {
                    (uri_path, Some(query_and_maybe_fragment), None)
                }
            } else if let Some((uri_path, fragment)) = post_host_str.split_once('#') {
                (uri_path, None, Some(fragment))
            } else {
                (post_host_str, None, None)
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
        let root_self_hash = selfhash::KERIHashStr::new_ref(root_self_hash_str)?;

        // Parse the query portion.
        let (query_self_hash_o, query_version_id_o) = if let Some(query) = query_o {
            parse_did_query_params(query)?
        } else {
            (None, None)
        };

        Ok(Self {
            host,
            path_o,
            root_self_hash,
            query_self_hash_o,
            query_version_id_o,
            fragment_o,
        })
    }
}
