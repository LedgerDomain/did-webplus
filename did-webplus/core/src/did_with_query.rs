use crate::{DIDURIComponents, DIDWithQueryStr, Error};

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
            hostname,
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
}
