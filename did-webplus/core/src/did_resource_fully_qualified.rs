use crate::{DIDResourceFullyQualifiedStr, DIDWebplusURIComponents, Error, Fragment};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(
    as_pneu_str = "as_did_fully_qualified_resource_str",
    borrow = "DIDResourceFullyQualifiedStr",
    deserialize,
    serialize,
    string_field = "1"
)]
pub struct DIDResourceFullyQualified<F: 'static + Fragment + ?Sized>(
    std::marker::PhantomData<F>,
    String,
);

/// Because DIDResourceFullyQualified has a type parameter that doesn't require Clone,
/// the standard derive(Clone) doesn't work, because it has incorrect, non-minimal bounds.
/// See https://github.com/rust-lang/rust/issues/41481
/// and https://github.com/rust-lang/rust/issues/26925
impl<F: Fragment + ?Sized> Clone for DIDResourceFullyQualified<F> {
    fn clone(&self) -> Self {
        Self(Default::default(), self.1.clone())
    }
}

impl<F: Fragment + ?Sized> DIDResourceFullyQualified<F> {
    pub fn new(
        hostname: &str,
        port_o: Option<u16>,
        path_o: Option<&str>,
        root_self_hash: &mbx::MBHashStr,
        query_self_hash: &mbx::MBHashStr,
        query_version_id: u32,
        fragment: &F,
    ) -> Result<Self, Error> {
        // TODO: Validation of hostname
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

        let s = DIDWebplusURIComponents {
            hostname,
            port_o,
            path_o,
            root_self_hash,
            query_self_hash_o: Some(query_self_hash),
            query_version_id_o: Some(query_version_id),
            // NOTE: It's not strictly correct that this is None while fragment_o is Some(_),
            // but for the purposes of to_string, it's fine.
            relative_resource_o: None,
            fragment_o: Some(fragment.as_str()),
        }
        .to_string();
        Self::try_from(s)
    }
}
