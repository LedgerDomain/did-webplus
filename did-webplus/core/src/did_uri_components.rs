use crate::{parse_did_query_params, DIDURILocatorComponents, Error};

/// Decomposition of a did:webplus URI into its components.
#[derive(Debug)]
pub struct DIDURIComponents<'a> {
    /// Optional locator component, which contains everything after "did:webplus:" and before the first '?' or '#'.
    // TODO: Allow this value to be None if the DID is a "VDG-only" DID, e.g. "did:webplus:<root-self-hash>".
    pub locator: DIDURILocatorComponents<'a>,
    /// The root self-hash of the root DID document.
    pub root_self_hash: &'a mbx::MBHashStr,
    /// Optional query param selfHash value.
    pub query_self_hash_o: Option<&'a mbx::MBHashStr>,
    /// Optional query param versionId value.
    pub query_version_id_o: Option<u32>,
    /// This is the fragment with the leading '#' char, if present.
    pub relative_resource_o: Option<&'a str>,
    /// The fragment without the leading '#' char.
    pub fragment_o: Option<&'a str>,
}

impl<'a> DIDURIComponents<'a> {
    pub fn hostname(&self) -> &'a str {
        self.locator.hostname
    }
    pub fn port_o(&self) -> Option<u16> {
        self.locator.port_o
    }
    pub fn path(&self) -> &'a str {
        self.locator.path
    }
    pub fn has_query(&self) -> bool {
        self.query_self_hash_o.is_some() || self.query_version_id_o.is_some()
    }
    pub fn has_fragment(&self) -> bool {
        self.fragment_o.is_some()
    }
}

impl<'a> std::fmt::Display for DIDURIComponents<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:webplus:{}", self.locator)?;
        write!(f, "{}", self.root_self_hash)?;
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
impl<'a> TryFrom<&'a str> for DIDURIComponents<'a> {
    type Error = Error;
    fn try_from(input_s: &'a str) -> Result<Self, Self::Error> {
        if !input_s.is_ascii() {
            return Err(Error::Malformed("did:webplus URI must be ASCII"));
        }
        if !input_s.starts_with("did:webplus:") {
            return Err(Error::Malformed(
                "did:webplus URI is expected to start with 'did:webplus:'",
            ));
        }
        // Get rid of the "did:webplus:" prefix.
        let s = input_s.strip_prefix("did:webplus:").unwrap();

        // Find the first '?' or '#' char, as that ends the non-query/fragment portion.
        let first_question_mark_index = s.find('?').unwrap_or(s.len());
        let first_hash_index = s.find('#').unwrap_or(s.len());
        let first_end_index = first_question_mark_index.min(first_hash_index);
        let locator_and_root_self_hash_str = &s[..first_end_index];

        // Split the locator and root-self-hash portions into their respective parts.
        if !locator_and_root_self_hash_str.contains('/') {
            return Err(Error::Malformed(
                "did:webplus URI is expected to contain a '/' before the root-self-hash",
            ));
        }
        let locator_end_index = locator_and_root_self_hash_str.rfind('/').unwrap() + 1;
        let locator_str = &locator_and_root_self_hash_str[..locator_end_index];
        let root_self_hash_str = &locator_and_root_self_hash_str[locator_end_index..];
        let locator = DIDURILocatorComponents::try_from(locator_str)?;
        let root_self_hash = mbx::MBHashStr::new_ref(root_self_hash_str)?;

        // Find the query and fragment portions, if present.
        let question_mark_and_query_str = &s[first_end_index..first_hash_index];
        let hash_and_fragment_str = &s[first_hash_index..];
        let (query_self_hash_o, query_version_id_o) =
            if question_mark_and_query_str.starts_with('?') {
                let query_str = question_mark_and_query_str.strip_prefix('?').unwrap();
                parse_did_query_params(query_str)?
            } else {
                (None, None)
            };
        let (relative_resource_o, fragment_o) = if hash_and_fragment_str.starts_with('#') {
            let relative_resource = hash_and_fragment_str;
            let fragment = hash_and_fragment_str.strip_prefix('#').unwrap();
            (Some(relative_resource), Some(fragment))
        } else {
            (None, None)
        };

        let did_uri_components = Self {
            locator,
            root_self_hash,
            query_self_hash_o,
            query_version_id_o,
            relative_resource_o,
            fragment_o,
        };

        Ok(did_uri_components)
    }
}
