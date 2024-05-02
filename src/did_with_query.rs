use std::{ops::Deref, str::FromStr};

use crate::{DIDURIComponents, DIDWithQueryAndFragment, Error, Fragment};

#[deprecated = "Use DIDWithQuery instead"]
pub type DIDWebplusWithQuery = DIDWithQuery;

#[derive(Debug, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
pub struct DIDWithQuery {
    pub(crate) host: String,
    pub(crate) path_o: Option<String>,
    pub(crate) self_hash: selfhash::KERIHash<'static>,
    pub(crate) query: String,
}

impl DIDWithQuery {
    pub fn new(
        host: String,
        path_o: Option<String>,
        self_hash: selfhash::KERIHash<'static>,
        query: String,
    ) -> Result<Self, Error> {
        // TODO: Validation of host
        // Validate path.  It must not begin or end with ':'.  Its components must be ':'-delimited.
        if let Some(path) = path_o.as_deref() {
            if path.starts_with(':') || path.ends_with(':') {
                return Err(Error::Malformed("DID path must not begin or end with ':'"));
            }
        }
        // TODO: Further validation of path.

        // Validate query params
        let mut query_self_hash_o = None;
        let mut query_version_id_o: Option<u32> = None;
        for query_param in query.split('&') {
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
                        return Err(Error::Malformed("Unrecognized query parameter"));
                    }
                }
            } else {
                return Err(Error::Malformed(
                    "Query parameter is missing a '='-delimited value",
                ));
            }
        }

        Ok(Self {
            host,
            path_o,
            self_hash,
            query,
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
            query: self.query.clone(),
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
    pub fn self_hash(&self) -> &selfhash::KERIHash<'static> {
        &self.self_hash
    }
    /// This is the query parameters portion of the DID URI, which typically includes the versionId
    /// and selfHash field values from the DID document current at the time the key was used.
    pub fn query(&self) -> &str {
        &self.query
    }
    pub fn query_self_hash(&self) -> Option<selfhash::KERIHash> {
        for query_param in self.query.split('&') {
            let (key, value) = query_param.split_once('=').expect(
                "programmer error: this should succeed due to the checks in the constructor",
            );
            if key == "selfHash" {
                return Some(selfhash::KERIHash::from_str(value).expect(
                    "programmer error: this should succeed due to the checks in the constructor",
                ));
            }
        }
        None
    }
    pub fn query_version_id(&self) -> Option<u32> {
        for query_param in self.query.split('&') {
            let (key, value) = query_param.split_once('=').expect(
                "programmer error: this should succeed due to the checks in the constructor",
            );
            if key == "versionId" {
                return Some(value.parse().expect(
                    "programmer error: this should succeed due to the checks in the constructor",
                ));
            }
        }
        None
    }
    /// Produce the URL that addresses the specified DID document for this DID.
    /// Based on the URL scheme for did:webplus, this is only well-defined if there is at most
    /// one query param (either selfHash or versionId).
    pub fn resolution_url(&self) -> String {
        // Form the base URL.
        // let mut url = format!("https://{}/", self.host);
        let mut url = format!("http://{}/", self.host); // TEMP HACK
        if let Some(path) = self.path_o.as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash.deref());
        url.push_str("/did");

        // Append query param portion of filename.
        let query_self_hash_o = self.query_self_hash();
        let query_version_id_o = self.query_version_id();
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
                        format!("selfHash={}", query_self_hash),
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
                        format!("selfHash={}", query_self_hash),
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
                        format!("versionId={}", query_version_id),
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
                        format!("versionId={}", query_version_id),
                    )?)
                }
            }
        } else {
            Err(Error::Malformed(
                "resolution URL path must end with '/did/selfHash/<hash>.json' or '/did/versionId/<#>.json'",
            ))
        }
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
            self.host, path, delimiter, self.self_hash, self.query
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
        let host = did_uri_components.host.to_string();
        let (path_o, self_hash_str) =
            if let Some((path, self_hash_str)) = did_uri_components.path.rsplit_once(':') {
                (Some(path), self_hash_str)
            } else {
                (None, did_uri_components.path)
            };
        let path_o = path_o.map(|s| s.into());
        let self_hash = selfhash::KERIHash::from_str(self_hash_str)?;
        if did_uri_components.query_o.is_none() {
            return Err(Error::Malformed("DID query is missing"));
        }
        let query = did_uri_components.query_o.unwrap().to_string();
        Ok(Self {
            host,
            path_o,
            self_hash,
            query,
        })
    }
}
