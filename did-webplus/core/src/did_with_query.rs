use crate::{DIDURIComponents, DIDURILocatorComponents, DIDWithQueryStr, Error};

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
        hostname: &str,
        port_o: Option<u16>,
        path_o: Option<&str>,
        root_self_hash: &mbx::MBHashStr,
        query_self_hash_o: Option<&mbx::MBHashStr>,
        query_version_id_o: Option<u32>,
    ) -> Result<Self, Error> {
        // TODO: Complete validation of hostname
        if hostname.contains(':') || hostname.contains('/') {
            return Err(Error::Malformed(
                "DIDFullyQualified hostname must not contain ':' or '/'",
            ));
        }
        if query_self_hash_o.is_none() && query_version_id_o.is_none() {
            return Err(Error::Malformed(
                "DIDWithQuery must have at least one query specified",
            ));
        }

        let s = DIDURIComponents {
            locator: DIDURILocatorComponents {
                hostname,
                port_o,
                path: if let Some(path) = path_o { path } else { "/" },
            },
            root_self_hash,
            query_self_hash_o,
            query_version_id_o,
            relative_resource_o: None,
            fragment_o: None,
        }
        .to_string();
        Self::try_from(s)
    }
    pub fn from_resolution_url(
        hostname: &str,
        port_o: Option<u16>,
        path_and_filename: &str,
    ) -> Result<Self, Error> {
        if !path_and_filename.ends_with(".json") {
            return Err(Error::Malformed(
                "resolution URL path must end with '.json'",
            ));
        }
        let (path, filename) = path_and_filename
            .rsplit_once('/')
            .ok_or_else(|| Error::Malformed("resolution URL path must contain a '/' character"))?;
        assert!(filename.ends_with(".json"));
        if path.ends_with("/did/selfHash") {
            let path = path.strip_suffix("/did/selfHash").unwrap();
            let query_self_hash_str = filename.strip_suffix(".json").unwrap();
            let query_self_hash = mbx::MBHashStr::new_ref(query_self_hash_str).map_err(|_| {
                Error::Malformed("invalid query self-hash in filename component of resolution URL")
            })?;
            let path_end_slash_index = path.rfind('/').ok_or_else(|| {
                Error::Malformed(
                    "resolution URL path must contain a '/' character before the root self-hash",
                )
            })?;
            let (path, root_self_hash_str) = (
                &path[..path_end_slash_index + 1],
                &path[path_end_slash_index + 1..],
            );
            let root_self_hash = mbx::MBHashStr::new_ref(root_self_hash_str).map_err(|_| {
                Error::Malformed("invalid root self-hash component of resolution URL")
            })?;
            Ok(Self::new(
                hostname,
                port_o,
                Some(path),
                root_self_hash,
                Some(query_self_hash),
                None,
            )?)
        } else if path.ends_with("/did/versionId") {
            let path = path.strip_suffix("/did/versionId").unwrap();
            let query_version_id_str = filename.strip_suffix(".json").unwrap();
            let query_version_id: u32 = query_version_id_str.parse().map_err(|_| {
                Error::Malformed("invalid query version ID in filename component of resolution URL")
            })?;
            let path_end_slash_index = path.rfind('/').ok_or_else(|| {
                Error::Malformed(
                    "resolution URL path must contain a '/' character before the root self-hash",
                )
            })?;
            let (path, root_self_hash_str) = (
                &path[..path_end_slash_index + 1],
                &path[path_end_slash_index + 1..],
            );
            let root_self_hash = mbx::MBHashStr::new_ref(root_self_hash_str).map_err(|_| {
                Error::Malformed("invalid root self-hash component of resolution URL")
            })?;
            Ok(Self::new(
                hostname,
                port_o,
                Some(path),
                root_self_hash,
                None,
                Some(query_version_id),
            )?)
        } else {
            Err(Error::Malformed(
                "resolution URL path must end with '/did/selfHash/<hash>.json' or '/did/versionId/<#>.json'",
            ))
        }
    }
}
