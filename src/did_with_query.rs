use std::{ops::Deref, str::FromStr};

use crate::{DIDURIComponents, DIDWithQueryAndFragment, Error, Fragment};

#[deprecated = "Use DIDWithQuery instead"]
pub type DIDWebplusWithQuery = DIDWithQuery;

// TODO: Consider renaming this to something like DIDFullyQualified (though this would only if
// both self_hash and version_id are present; there would be other variants for partial qualification)
#[derive(Clone, Debug, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
pub struct DIDWithQuery {
    // TODO: Maybe just use DID instead of repeating the fields host, path_o, self_hash?
    pub(crate) host: String,
    pub(crate) path_o: Option<String>,
    pub(crate) self_hash: selfhash::KERIHash,
    pub(crate) query_self_hash_o: Option<selfhash::KERIHash>,
    pub(crate) query_version_id_o: Option<u32>,
}

impl DIDWithQuery {
    pub fn new(
        host: String,
        path_o: Option<String>,
        self_hash: selfhash::KERIHash,
        query_self_hash_o: Option<selfhash::KERIHash>,
        query_version_id_o: Option<u32>,
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
        })
    }
    pub fn without_query(&self) -> crate::DID {
        crate::DID {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
        }
    }
    pub fn with_fragment<F: Fragment>(&self, fragment: F) -> DIDWithQueryAndFragment<F> {
        DIDWithQueryAndFragment {
            host: self.host.clone(),
            path_o: self.path_o.clone(),
            self_hash: self.self_hash.clone(),
            query_self_hash_o: self.query_self_hash_o.clone(),
            query_version_id_o: self.query_version_id_o,
            fragment: fragment.into(),
        }
    }
    /// Host of the VDR that acts as the authority/origin for this DID.
    pub fn host(&self) -> &str {
        &self.host
    }
    /// This is everything between the host and the self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz"
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
    pub fn query_self_hash_o(&self) -> Option<&selfhash::KERIHash> {
        self.query_self_hash_o.as_ref()
    }
    pub fn query_version_id_o(&self) -> Option<u32> {
        self.query_version_id_o
    }
    /// Produce the URL that addresses the specified DID document for this DID.
    /// Based on the URL scheme for did:webplus, this is only well-defined if there is at most
    /// one query param (either selfHash or versionId).
    pub fn resolution_url(&self, scheme: &'static str) -> String {
        // Form the base URL.
        let mut url = format!("{}://{}/", scheme, self.host);
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did");

        // Append query param portion of filename.
        let query_self_hash_o = self.query_self_hash_o();
        let query_version_id_o = self.query_version_id_o();
        match (query_self_hash_o, query_version_id_o) {
            (Some(query_self_hash), _) => {
                // We only use the selfHash to form the URL in this case.
                // Note that %3D is the URL-encoding of '='
                url.push_str("/selfHash/");
                url.push_str(query_self_hash.deref());
            }
            (None, Some(query_version_id)) => {
                // We use the versionId to form the URL in this case.
                // Note that %3D is the URL-encoding of '='
                url.push_str("/versionId/");
                url.push_str(&query_version_id.to_string());
            }
            (None, None) => {
                // Add nothing.
            }
        }
        url.push_str(".json");

        url
    }
    pub fn from_resolution_url(host: &str, path: &str) -> Result<Self, Error> {
        if !path.ends_with(".json") {
            return Err(Error::Malformed(
                "resolution URL path must end with '.json'",
            ));
        }
        let (path, filename) = path
            .rsplit_once('/')
            .ok_or_else(|| Error::Malformed("resolution URL path must contain a '/' character"))?;
        assert!(filename.ends_with(".json"));
        if path.ends_with("/did/selfHash") {
            let path = path.strip_suffix("/did/selfHash").unwrap();
            let query_self_hash_str = filename.strip_suffix(".json").unwrap();
            let query_self_hash =
                selfhash::KERIHash::from_str(query_self_hash_str).map_err(|_| {
                    Error::Malformed("invalid self-hash in filename component of resolution URL")
                })?;
            match path.rsplit_once('/') {
                Some((path, did_self_hash_str)) => {
                    let did_self_hash =
                        selfhash::KERIHash::from_str(did_self_hash_str).map_err(|_| {
                            Error::Malformed("invalid self-hash component of resolution URL")
                        })?;
                    Ok(Self::new(
                        host.to_string(),
                        Some(path.to_string()),
                        did_self_hash,
                        Some(query_self_hash),
                        None,
                    )?)
                }
                None => {
                    let did_self_hash = selfhash::KERIHash::from_str(path).map_err(|_| {
                        Error::Malformed("invalid self-hash component of resolution URL")
                    })?;
                    Ok(Self::new(
                        host.to_string(),
                        None,
                        did_self_hash,
                        Some(query_self_hash),
                        None,
                    )?)
                }
            }
        } else if path.ends_with("/did/versionId") {
            let path = path.strip_suffix("/did/versionId").unwrap();
            let query_version_id_str = filename.strip_suffix(".json").unwrap();
            let query_version_id: u32 = query_version_id_str.parse().map_err(|_| {
                Error::Malformed("invalid version ID in filename component of resolution URL")
            })?;
            match path.rsplit_once('/') {
                Some((path, did_self_hash_str)) => {
                    let did_self_hash =
                        selfhash::KERIHash::from_str(did_self_hash_str).map_err(|_| {
                            Error::Malformed("invalid self-hash component of resolution URL")
                        })?;
                    Ok(Self::new(
                        host.to_string(),
                        Some(path.to_string()),
                        did_self_hash,
                        None,
                        Some(query_version_id),
                    )?)
                }
                None => {
                    let did_self_hash = selfhash::KERIHash::from_str(path).map_err(|_| {
                        Error::Malformed("invalid self-hash component of resolution URL")
                    })?;
                    Ok(Self::new(
                        host.to_string(),
                        None,
                        did_self_hash,
                        None,
                        Some(query_version_id),
                    )?)
                }
            }
        } else {
            Err(Error::Malformed(
                "resolution URL path must end with '/did/selfHash/<hash>.json' or '/did/versionId/<#>.json'",
            ))
        }
    }
    pub fn parse_query_params(
        query_params: &str,
    ) -> Result<(Option<selfhash::KERIHash>, Option<u32>), Error> {
        let mut query_self_hash_o = None;
        let mut query_version_id_o: Option<u32> = None;
        for query_param in query_params.split('&') {
            if let Some((key, value)) = query_param.split_once('=') {
                match key {
                    "selfHash" => {
                        // If query_self_hash_o is already set, then this is a duplicate query param
                        if query_self_hash_o.is_some() {
                            return Err(Error::Malformed("Multiple selfHash query parameters"));
                        }
                        query_self_hash_o = Some(selfhash::KERIHash::from_str(value)?);
                    }
                    "versionId" => {
                        // If query_version_id_o is already set, then this is a duplicate query param
                        if query_version_id_o.is_some() {
                            return Err(Error::Malformed("Multiple versionId query parameters"));
                        }
                        query_version_id_o = Some(
                            value
                                .parse()
                                .map_err(|_| "versionId query parameter expected a u32 value")?,
                        );
                    }
                    _ => {
                        return Err(Error::Malformed("Unrecognized query parameter; only selfHash and versionId are recognized"));
                    }
                }
            } else {
                return Err(Error::Malformed(
                    "Query parameter is missing a '='-delimited value",
                ));
            }
        }
        Ok((query_self_hash_o, query_version_id_o))
    }
}

impl std::fmt::Display for DIDWithQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (path, delimiter) = if let Some(path) = self.path_o.as_deref() {
            (path, ":")
        } else {
            ("", "")
        };
        write!(
            f,
            "did:webplus:{}:{}{}{}?{}",
            self.host,
            path,
            delimiter,
            self.self_hash,
            self.query_params()
        )
    }
}

impl std::str::FromStr for DIDWithQuery {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_uri_components = DIDURIComponents::try_from(s)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        if did_uri_components.query_o.is_none() {
            return Err(Error::Malformed("DID query is missing"));
        }
        if did_uri_components.fragment_o.is_some() {
            return Err(Error::Malformed("DIDWithQuery must not have a fragment"));
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
            Self::parse_query_params(did_uri_components.query_o.unwrap())?;

        Self::new(
            host,
            path_o,
            self_hash,
            query_self_hash_o,
            query_version_id_o,
        )
    }
}
