use crate::{DIDFragment, DIDURIComponents, DIDWithQueryAndFragment, Error, Fragment, DID};

#[deprecated = "Use DIDWithFragment instead"]
pub type DIDWebplusWithFragment<F> = DIDWithFragment<F>;

#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, PartialEq, serde_with::SerializeDisplay,
)]
pub struct DIDWithFragment<F: Fragment> {
    pub(crate) host: String,
    pub(crate) path_o: Option<String>,
    pub(crate) self_hash: selfhash::KERIHash<'static>,
    pub(crate) fragment: DIDFragment<F>,
}

impl<F: Fragment> DIDWithFragment<F> {
    pub fn new(
        host: String,
        path_o: Option<String>,
        self_hash: selfhash::KERIHash<'static>,
        fragment: DIDFragment<F>,
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
            fragment,
        })
    }
    pub fn without_fragment(&self) -> DID {
        DID {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
        }
    }
    pub fn with_query(&self, query: String) -> DIDWithQueryAndFragment<F> {
        DIDWithQueryAndFragment {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
            query,
            fragment: self.fragment.clone(),
        }
    }
    /// Host of the VDR that acts as the authority/origin for this DID.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// This is everything between the host and the self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.path_o.as_deref()
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn self_hash(&self) -> &selfhash::KERIHash<'static> {
        &self.self_hash
    }
    /// This is the fragment portion of the DID URI, which is typically a key ID, but could refer to another
    /// resource within the DID document.
    pub fn fragment(&self) -> &DIDFragment<F> {
        &self.fragment
    }
}

impl<F: Fragment> std::fmt::Display for DIDWithFragment<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note that the fragment includes the leading '#' when it is displayed.
        let (path, delimiter) = if let Some(path) = self.path_o.as_deref() {
            (path, ":")
        } else {
            ("", "")
        };
        write!(
            f,
            "did:webplus:{}:{}{}{}{}",
            self.host, path, delimiter, self.self_hash, self.fragment
        )
    }
}

impl<F: Fragment> std::str::FromStr for DIDWithFragment<F> {
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
        if did_uri_components.fragment_o.is_none() {
            return Err(Error::Malformed("DID fragment is missing"));
        }
        let fragment = DIDFragment::from_str_without_hash(did_uri_components.fragment_o.unwrap())?;
        Ok(Self {
            host,
            path_o,
            self_hash,
            fragment,
        })
    }
}
