use crate::{DIDWithQueryStr, Error};

// pub enum DIDQueryParams<'a> {
//     SelfHash(&'a selfhash::KERIHashStr),
//     FullyQualified(&'a selfhash::KERIHashStr, u32),
//     VersionId(u32),
// }

/// A DIDWithQuery is a DID that has at least one query param specified (selfHash and/or versionId).
#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(
    as_pneu_str = "as_did_with_query_str",
    borrow = "DIDWithQueryStr",
    deserialize,
    serialize
)]
pub struct DIDWithQuery(String);

impl DIDWithQuery {
    pub fn new(
        host: &str,
        path_o: Option<&str>,
        root_self_hash: &selfhash::KERIHashStr,
        query_self_hash_o: Option<&selfhash::KERIHashStr>,
        query_version_id_o: Option<u32>,
    ) -> Result<Self, Error> {
        // TODO: Complete validation of host
        if host.contains(':') || host.contains('/') {
            return Err(Error::Malformed(
                "DIDFullyQualified host must not contain ':' or '/'",
            ));
        }
        let did_with_query_string = match (query_self_hash_o, query_version_id_o) {
            (Some(query_self_hash), Some(query_version_id)) => {
                format!(
                    "did:webplus:{}{}{}:{}?selfHash={}&versionId={}",
                    host,
                    if path_o.is_some() { ":" } else { "" },
                    if let Some(path) = path_o { path } else { "" },
                    root_self_hash,
                    query_self_hash,
                    query_version_id
                )
            }
            (Some(query_self_hash), None) => {
                format!(
                    "did:webplus:{}{}{}:{}?selfHash={}",
                    host,
                    if path_o.is_some() { ":" } else { "" },
                    if let Some(path) = path_o { path } else { "" },
                    root_self_hash,
                    query_self_hash
                )
            }
            (None, Some(query_version_id)) => {
                format!(
                    "did:webplus:{}{}{}:{}?versionId={}",
                    host,
                    if path_o.is_some() { ":" } else { "" },
                    if let Some(path) = path_o { path } else { "" },
                    root_self_hash,
                    query_version_id
                )
            }
            (None, None) => {
                return Err(Error::Malformed(
                    "DIDWithQuery must have at least one query specified",
                ));
            }
        };
        Self::try_from(did_with_query_string)
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
                selfhash::KERIHashStr::new_ref(query_self_hash_str).map_err(|_| {
                    Error::Malformed(
                        "invalid query self-hash in filename component of resolution URL",
                    )
                })?;
            match path.rsplit_once('/') {
                Some((path, root_self_hash_str)) => {
                    let root_self_hash = selfhash::KERIHashStr::new_ref(root_self_hash_str)
                        .map_err(|_| {
                            Error::Malformed("invalid root self-hash component of resolution URL")
                        })?;
                    Ok(Self::new(
                        host,
                        Some(path),
                        root_self_hash,
                        Some(query_self_hash),
                        None,
                    )?)
                }
                None => {
                    let root_self_hash = selfhash::KERIHashStr::new_ref(path).map_err(|_| {
                        Error::Malformed("invalid root self-hash component of resolution URL")
                    })?;
                    Ok(Self::new(
                        host,
                        None,
                        root_self_hash,
                        Some(query_self_hash),
                        None,
                    )?)
                }
            }
        } else if path.ends_with("/did/versionId") {
            let path = path.strip_suffix("/did/versionId").unwrap();
            let query_version_id_str = filename.strip_suffix(".json").unwrap();
            let query_version_id: u32 = query_version_id_str.parse().map_err(|_| {
                Error::Malformed("invalid query version ID in filename component of resolution URL")
            })?;
            match path.rsplit_once('/') {
                Some((path, root_self_hash_str)) => {
                    let root_self_hash = selfhash::KERIHashStr::new_ref(root_self_hash_str)
                        .map_err(|_| {
                            Error::Malformed("invalid root self-hash component of resolution URL")
                        })?;
                    Ok(Self::new(
                        host,
                        Some(path),
                        root_self_hash,
                        None,
                        Some(query_version_id),
                    )?)
                }
                None => {
                    let root_self_hash = selfhash::KERIHashStr::new_ref(path).map_err(|_| {
                        Error::Malformed("invalid root self-hash component of resolution URL")
                    })?;
                    Ok(Self::new(
                        host,
                        None,
                        root_self_hash,
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
}
