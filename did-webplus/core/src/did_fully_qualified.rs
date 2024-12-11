use crate::{DIDFullyQualifiedStr, DIDWebplusURIComponents, Error};

/// A DIDFullyQualified is a DID that has query params selfHash and versionId specified.
#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(
    as_pneu_str = "as_did_fully_qualified_str",
    borrow = "DIDFullyQualifiedStr",
    deserialize,
    serialize
)]
pub struct DIDFullyQualified(String);

impl DIDFullyQualified {
    /// Construct a DIDFullyQualified with specified components.
    pub fn new(
        host: &str,
        port_o: Option<u16>,
        path_o: Option<&str>,
        root_self_hash: &selfhash::KERIHashStr,
        query_self_hash: &selfhash::KERIHashStr,
        query_version_id: u32,
    ) -> Result<Self, Error> {
        // TODO: Complete validation of host
        if host.contains(':') || host.contains('/') {
            return Err(Error::Malformed(
                "DIDFullyQualified host must not contain ':' or '/'",
            ));
        }

        let s = DIDWebplusURIComponents {
            host,
            port_o,
            path_o,
            root_self_hash,
            query_self_hash_o: Some(query_self_hash),
            query_version_id_o: Some(query_version_id),
            relative_resource_o: None,
            fragment_o: None,
        }
        .to_string();
        Self::try_from(s)
    }
}
