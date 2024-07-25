use crate::{
    DIDFragment, DIDURIComponents, Error, Fragment, ParsedDIDWithFragment, ParsedDIDWithQuery,
};

#[deprecated = "Use DIDWithQueryAndFragment instead"]
pub type DIDWebplusWithQueryAndFragment<F> = ParsedDIDWithQueryAndFragment<F>;

// TODO: Consider renaming this to something like DIDResourceFullyQualified
#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, Hash, PartialEq, serde_with::SerializeDisplay,
)]
pub struct ParsedDIDWithQueryAndFragment<F: Fragment> {
    // TODO: Maybe just use DIDWithQuery instead of repeating the fields host, path_o, self_hash, query_*?
    pub(crate) host: String,
    pub(crate) path_o: Option<String>,
    pub(crate) self_hash: selfhash::KERIHash,
    pub(crate) query_self_hash_o: Option<selfhash::KERIHash>,
    pub(crate) query_version_id_o: Option<u32>,
    pub(crate) fragment: DIDFragment<F>,
}

impl<F: Fragment> ParsedDIDWithQueryAndFragment<F> {
    pub fn new(
        host: String,
        path_o: Option<String>,
        self_hash: selfhash::KERIHash,
        query_self_hash_o: Option<selfhash::KERIHash>,
        query_version_id_o: Option<u32>,
        fragment: DIDFragment<F>,
    ) -> Result<Self, Error> {
        // TODO: Validation of host
        // Validate path.  It must not begin or end with ':'.  Its components must be ':'-delimited.
        if let Some(path) = path_o.as_deref() {
            if path.starts_with(':') || path.ends_with(':') {
                return Err(Error::Malformed("DID path must not begin or end with ':'"));
            }
            if path.contains('/') {
                return Err(Error::Malformed("DID path must not contain '/'"));
            }
        }
        // TODO: Further validation of path.

        if query_self_hash_o.is_none() && query_version_id_o.is_none() {
            return Err(Error::Malformed(
                "DIDWithQuery must have at least one of query_self_hash_o or query_version_id_o",
            ));
        }

        Ok(Self {
            host,
            path_o,
            self_hash,
            query_self_hash_o,
            query_version_id_o,
            fragment,
        })
    }
    pub fn without_query(&self) -> ParsedDIDWithFragment<F> {
        ParsedDIDWithFragment::new(
            self.host.clone(),
            self.path_o.clone(),
            self.self_hash.clone(),
            self.fragment.clone(),
        )
        .expect("programmer error")
    }
    pub fn without_fragment(&self) -> ParsedDIDWithQuery {
        ParsedDIDWithQuery {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
            query_self_hash_o: self.query_self_hash_o.clone(),
            query_version_id_o: self.query_version_id_o,
        }
    }
    /// Host of the VDR that acts as the authority/origin for this DID.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// This is everything between the host and the self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.path_o.as_deref()
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn self_hash(&self) -> &selfhash::KERIHash {
        &self.self_hash
    }
    /// This is the string-formatted query parameters portion of the DID URI, in which the selfHash and
    /// versionId parameters from the DID document current at the time the key was used are formatted in
    /// canonical form.
    pub fn query_params(&self) -> String {
        match (self.query_self_hash_o.as_ref(), self.query_version_id_o) {
            (Some(query_self_hash), Some(query_version_id)) => {
                format!(
                    "selfHash={}&versionId={}",
                    query_self_hash, query_version_id
                )
            }
            (Some(query_self_hash), None) => format!("selfHash={}", query_self_hash),
            (None, Some(query_version_id)) => format!("versionId={}", query_version_id),
            (None, None) => {
                panic!("programmer error: this should not be possible due to the checks in the constructor")
            }
        }
    }
    pub fn query_self_hash_o(&self) -> Option<&selfhash::KERIHashStr> {
        self.query_self_hash_o.as_deref()
    }
    pub fn query_version_id_o(&self) -> Option<u32> {
        self.query_version_id_o
    }
    /// This is the fragment portion of the DID URI, which is typically a key ID, but could refer to another
    /// resource within the DID document.
    pub fn fragment(&self) -> &DIDFragment<F> {
        &self.fragment
    }
}

impl<F: Fragment> std::fmt::Display for ParsedDIDWithQueryAndFragment<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note that the fragment includes the leading '#' when it is displayed.
        let (path, delimiter) = if let Some(path) = self.path_o.as_deref() {
            (path, ":")
        } else {
            ("", "")
        };
        write!(
            f,
            "did:webplus:{}:{}{}{}?{}{}",
            self.host,
            path,
            delimiter,
            self.self_hash,
            self.query_params(),
            self.fragment
        )
    }
}

impl<F: Fragment> std::str::FromStr for ParsedDIDWithQueryAndFragment<F> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_uri_components = DIDURIComponents::try_from(s)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        if did_uri_components.query_o.is_none() {
            return Err(Error::Malformed("DID query is missing"));
        }
        if did_uri_components.fragment_o.is_none() {
            return Err(Error::Malformed("DID fragment is missing"));
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

        let (query_self_hash_o, query_version_id_o) =
            ParsedDIDWithQuery::parse_query_params(did_uri_components.query_o.unwrap())?;

        let fragment = DIDFragment::from_str_without_hash(did_uri_components.fragment_o.unwrap())?;
        Ok(Self {
            host,
            path_o,
            self_hash,
            query_self_hash_o,
            query_version_id_o,
            fragment,
        })
    }
}
