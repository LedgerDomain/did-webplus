use crate::{DIDFullyQualifiedStr, Error};

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
        path_o: Option<&str>,
        self_hash: &selfhash::KERIHashStr,
        query_self_hash: &selfhash::KERIHashStr,
        query_version_id: u32,
    ) -> Result<Self, Error> {
        // TODO: Complete validation of host
        if host.contains(':') || host.contains('/') {
            return Err(Error::Malformed(
                "DIDFullyQualified host must not contain ':' or '/'",
            ));
        }
        Self::try_from(format!(
            "did:webplus:{}{}{}:{}?selfHash={}&versionId={}",
            host,
            if path_o.is_some() { ":" } else { "" },
            if let Some(path) = path_o { path } else { "" },
            self_hash,
            query_self_hash,
            query_version_id
        ))
    }
}
