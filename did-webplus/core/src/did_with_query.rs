use crate::{DIDWebplusURIComponents, DIDWithQueryStr, Error};

// pub enum DIDQueryParams<'a> {
//     SelfHash(&'a mbx::MBHashStr),
//     FullyQualified(&'a mbx::MBHashStr, u32),
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
        port_o: Option<u16>,
        path_o: Option<&str>,
        root_self_hash: &mbx::MBHashStr,
        query_self_hash_o: Option<&mbx::MBHashStr>,
        query_version_id_o: Option<u32>,
    ) -> Result<Self, Error> {
        // TODO: Complete validation of host
        if host.contains(':') || host.contains('/') {
            return Err(Error::Malformed(
                "DIDFullyQualified host must not contain ':' or '/'",
            ));
        }
        if query_self_hash_o.is_none() && query_version_id_o.is_none() {
            return Err(Error::Malformed(
                "DIDWithQuery must have at least one query specified",
            ));
        }

        let s = DIDWebplusURIComponents {
            host,
            port_o,
            path_o,
            root_self_hash,
            query_self_hash_o,
            query_version_id_o,
            relative_resource_o: None,
            fragment_o: None,
        }
        .to_string();
        Self::try_from(s)
    }
    pub fn from_resolution_url(host: &str, port_o: Option<u16>, path: &str) -> Result<Self, Error> {
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
            let query_self_hash = mbx::MBHashStr::new_ref(query_self_hash_str).map_err(|_| {
                Error::Malformed("invalid query self-hash in filename component of resolution URL")
            })?;
            match path.rsplit_once('/') {
                Some((path, root_self_hash_str)) => {
                    let root_self_hash =
                        mbx::MBHashStr::new_ref(root_self_hash_str).map_err(|_| {
                            Error::Malformed("invalid root self-hash component of resolution URL")
                        })?;
                    Ok(Self::new(
                        host,
                        port_o,
                        Some(path),
                        root_self_hash,
                        Some(query_self_hash),
                        None,
                    )?)
                }
                None => {
                    let root_self_hash = mbx::MBHashStr::new_ref(path).map_err(|_| {
                        Error::Malformed("invalid root self-hash component of resolution URL")
                    })?;
                    Ok(Self::new(
                        host,
                        port_o,
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
                    let root_self_hash =
                        mbx::MBHashStr::new_ref(root_self_hash_str).map_err(|_| {
                            Error::Malformed("invalid root self-hash component of resolution URL")
                        })?;
                    Ok(Self::new(
                        host,
                        port_o,
                        Some(path),
                        root_self_hash,
                        None,
                        Some(query_version_id),
                    )?)
                }
                None => {
                    let root_self_hash = mbx::MBHashStr::new_ref(path).map_err(|_| {
                        Error::Malformed("invalid root self-hash component of resolution URL")
                    })?;
                    Ok(Self::new(
                        host,
                        port_o,
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
