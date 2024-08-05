use crate::{DIDFragment, DIDResourceFullyQualifiedStr, Error, Fragment};

#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(
    as_pneu_str = "as_did_fully_qualified_resource_str",
    borrow = "DIDResourceFullyQualifiedStr",
    deserialize,
    serialize,
    string_field = "1"
)]
pub struct DIDResourceFullyQualified<F: 'static + Fragment>(std::marker::PhantomData<F>, String);

impl<F: Fragment> DIDResourceFullyQualified<F> {
    pub fn new(
        host: &str,
        path_o: Option<&str>,
        root_self_hash: &selfhash::KERIHashStr,
        query_self_hash: &selfhash::KERIHashStr,
        query_version_id: u32,
        // TODO: This should be just F, or &F::Borrowed or something.
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

        Self::try_from(format!(
            "did:webplus:{}{}{}:{}?selfHash={}&versionId={}{}",
            host,
            if path_o.is_some() { ":" } else { "" },
            if let Some(path) = path_o { path } else { "" },
            root_self_hash,
            query_self_hash,
            query_version_id,
            fragment
        ))
    }
}
