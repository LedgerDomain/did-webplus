use crate::{DIDURIComponents, DIDWithFragment, DIDWithQuery, Error, Fragment};

#[deprecated = "Use DID instead"]
pub type DIDWebplus = DID;

#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, PartialEq, Hash, serde_with::SerializeDisplay,
)]
pub struct DID {
    pub(crate) host: String,
    pub(crate) path_o: Option<String>,
    pub(crate) self_hash: selfhash::KERIHash<'static>,
}

impl DID {
    pub fn new(
        host: String,
        path_o: Option<String>,
        self_hash: selfhash::KERIHash<'static>,
    ) -> Result<Self, Error> {
        // TODO: Validation of host
        // Validate path.  It must not begin or end with ':'.  Its components must be ':'-delimited.
        if let Some(path) = path_o.as_deref() {
            if path.starts_with(':') || path.ends_with(':') {
                return Err(Error::Malformed("DID path must not begin or end with ':'"));
            }
        }
        // TODO: Further validation of path.
        Ok(Self {
            host,
            path_o,
            self_hash,
        })
    }
    pub fn with_query(&self, query: String) -> DIDWithQuery {
        DIDWithQuery {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
            query,
        }
    }
    pub fn with_fragment<F: Fragment>(&self, fragment: F) -> DIDWithFragment<F> {
        DIDWithFragment {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
            fragment: fragment.into(),
        }
    }
    /// Host of the VDR that acts as the authority/origin for this DID.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// This is everything between the host and the self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ" which will have path_o
    /// of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.path_o.as_deref()
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn self_hash(&self) -> &selfhash::KERIHash<'static> {
        &self.self_hash
    }
}

impl std::fmt::Display for DID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (path, delimiter) = if let Some(path) = self.path_o.as_deref() {
            (path, ":")
        } else {
            ("", "")
        };
        write!(
            f,
            "did:webplus:{}:{}{}{}",
            self.host, path, delimiter, self.self_hash
        )
    }
}

impl std::str::FromStr for DID {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_uri_components = DIDURIComponents::try_from(s)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        let host = did_uri_components.host.to_string();
        let (path_o, self_hash_str) =
            if let Some((path, self_hash_str)) = did_uri_components.path.rsplit_once(':') {
                (Some(path), self_hash_str)
            } else {
                (None, did_uri_components.path)
            };
        let path_o = path_o.map(|s| s.into());
        let self_hash = selfhash::KERIHash::from_str(self_hash_str)?;
        Ok(Self {
            host,
            path_o,
            self_hash,
        })
    }
}
