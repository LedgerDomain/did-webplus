use std::ops::Deref;

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
    /// This is equivalent to DID::new, but it doesn't require the caller to convert the self_hash
    /// string to a KERIHash itself.
    pub fn new_with_self_hash_string(
        host: String,
        path_o: Option<String>,
        self_hash_string: String,
    ) -> Result<Self, Error> {
        // TODO: Use KERIHash::try_from once it's implemented.
        use std::str::FromStr;
        let self_hash = selfhash::KERIHash::from_str(&self_hash_string)?;
        Self::new(host, path_o, self_hash)
    }
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
            if path.contains('/') {
                return Err(Error::Malformed("DID path must not contain '/'"));
            }
        }
        // TODO: Further validation of path.
        Ok(Self {
            host,
            path_o,
            self_hash,
        })
    }
    pub fn with_query_self_hash(
        &self,
        query_self_hash: selfhash::KERIHash<'static>,
    ) -> DIDWithQuery {
        DIDWithQuery {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
            query_self_hash_o: Some(query_self_hash),
            query_version_id_o: None,
        }
    }
    pub fn with_query_version_id(&self, query_version_id: u32) -> DIDWithQuery {
        DIDWithQuery {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
            query_self_hash_o: None,
            query_version_id_o: Some(query_version_id),
        }
    }
    pub fn with_queries(
        &self,
        query_self_hash: selfhash::KERIHash<'static>,
        query_version_id: u32,
    ) -> DIDWithQuery {
        DIDWithQuery {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
            query_self_hash_o: Some(query_self_hash),
            query_version_id_o: Some(query_version_id),
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
    /// Produce the URL that addresses the latest DID document for this DID.
    pub fn resolution_url(&self, scheme: &'static str) -> String {
        let mut url = format!("{}://{}/", scheme, self.host);
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did.json");
        url
    }
    /// Produce the URL that addresses the DID document for this DID that has the given self-hash.
    pub fn resolution_url_for_self_hash(
        &self,
        self_hash_str: &str,
        scheme: &'static str,
    ) -> String {
        let mut url = format!("{}://{}/", scheme, self.host);
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did/selfHash/");
        url.push_str(self_hash_str);
        url.push_str(".json");
        url
    }
    /// Produce the URL that addresses the DID document for this DID that has the given version ID.
    pub fn resolution_url_for_version_id(&self, version_id: u32, scheme: &'static str) -> String {
        let mut url = format!("{}://{}/", scheme, self.host);
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did/versionId/");
        url.push_str(&format!("{}.json", version_id));
        url
    }
    /// Produce the URL that addresses the current DID document metadata for this DID.
    pub fn resolution_url_for_metadata_current(&self, scheme: &'static str) -> String {
        let mut url = format!("{}://{}/", scheme, self.host);
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did/metadata.json");
        url
    }
    /// Produce the URL that addresses the constant DID document metadata for this DID
    /// (in particular, this includes DID creation timestamp).
    pub fn resolution_url_for_metadata_constant(&self, scheme: &'static str) -> String {
        let mut url = format!("{}://{}/", scheme, self.host);
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did/metadata/constant.json");
        url
    }
    /// Produce the URL that addresses the idempotent portion of the DID document metadata for
    /// this DID that has the given self-hash.
    pub fn resolution_url_for_metadata_idempotent_for_self_hash(
        &self,
        self_hash_str: &str,
        scheme: &'static str,
    ) -> String {
        let mut url = format!("{}://{}/", scheme, self.host);
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did/metadata/selfHash/");
        url.push_str(self_hash_str);
        url.push_str(".json");
        url
    }
    /// Produce the URL that addresses the idempotent portion of the DID document metadata for this
    /// DID that has the given version ID.
    pub fn resolution_url_for_metadata_idempotent_for_version_id(
        &self,
        version_id: u32,
        scheme: &'static str,
    ) -> String {
        let mut url = format!("{}://{}/", scheme, self.host);
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did/metadata/versionId/");
        url.push_str(&format!("{}.json", version_id));
        url
    }
    /// Parse (the equivalent of) a resolution URL to produce a DID.
    pub fn from_resolution_url(host: &str, path: &str) -> Result<Self, Error> {
        if path.starts_with('/') {
            return Err(Error::Malformed(
                "resolution URL path must not start with '/'",
            ));
        }
        if !path.ends_with("/did.json") {
            return Err(Error::Malformed(
                "resolution URL path must end with 'did.json'",
            ));
        }
        let path_and_self_hash_str = path.strip_suffix("/did.json").unwrap();
        match path_and_self_hash_str.rsplit_once('/') {
            Some((path, self_hash_str)) => {
                // Replace all the '/' chars with ':' chars.
                let path = path.replace('/', ":");
                Self::new_with_self_hash_string(
                    host.to_string(),
                    Some(path),
                    self_hash_str.to_string(),
                )
            }
            None => {
                let self_hash_str = path_and_self_hash_str;
                return Self::new_with_self_hash_string(
                    host.to_string(),
                    None,
                    self_hash_str.to_string(),
                );
            }
        }
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
        if did_uri_components.query_o.is_some() {
            return Err(Error::Malformed("DID must not have a query"));
        }
        if did_uri_components.fragment_o.is_some() {
            return Err(Error::Malformed("DID must not have a fragment"));
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
