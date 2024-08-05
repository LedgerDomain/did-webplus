use crate::{DIDFragment, DIDResourceStr, Error, Fragment};

#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(
    as_pneu_str = "as_did_resource_str",
    borrow = "DIDResourceStr",
    deserialize,
    serialize,
    string_field = "1"
)]
pub struct DIDResource<F: 'static + Fragment>(std::marker::PhantomData<F>, String);

impl<F: 'static + Fragment> DIDResource<F> {
    pub fn new(
        host: &str,
        path_o: Option<&str>,
        self_hash: &selfhash::KERIHashStr,
        // TODO: Use DIDFragmentStr when it exists
        fragment: &DIDFragment<F>,
    ) -> Result<Self, Error> {
        // TODO: Complete validation of host
        if host.contains(':') || host.contains('/') {
            return Err(Error::Malformed(
                "DIDResource host must not contain ':' or '/'",
            ));
        }
        Self::try_from(format!(
            "did:webplus:{}{}{}:{}{}",
            host,
            if path_o.is_some() { ":" } else { "" },
            if let Some(path) = path_o { path } else { "" },
            self_hash,
            fragment
        ))
    }
    pub fn set_self_hash(&mut self, self_hash: &selfhash::KERIHashStr) {
        assert_eq!(self.self_hash().len(), self_hash.len(), "programmer error: hash function must already be known, producing a known, fixed length for the DID's root self-hash component");
        let end = self.find('#').unwrap();
        assert!(end > self.self_hash().len());
        let begin = end - self.self_hash().len();
        self.1.replace_range(begin..end, self_hash.as_str());
        debug_assert!(
            <DIDResourceStr::<F> as pneutype::Validate>::validate(self.1.as_str()).is_ok()
        );
    }
}

/// This implementation is to allow a `&DIDResource` to function as a `&dyn selfhash::Hash`, which is necessary
/// for the self-hashing functionality.  A DIDResource isn't strictly "a Hash", more like it "has a Hash", but
/// this semantic difference isn't worth doing anything about.
impl<F: 'static + Fragment> selfhash::Hash for DIDResource<F> {
    fn hash_function(&self) -> &dyn selfhash::HashFunction {
        self.self_hash().hash_function()
    }
    fn to_hash_bytes<'s: 'h, 'h>(&'s self) -> selfhash::HashBytes<'h> {
        self.self_hash().to_hash_bytes()
    }
    fn to_keri_hash<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, selfhash::KERIHashStr> {
        std::borrow::Cow::Borrowed(self.self_hash())
    }
}
