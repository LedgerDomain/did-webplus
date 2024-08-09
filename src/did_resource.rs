use std::borrow::Cow;

use crate::{DIDResourceStr, Error, Fragment};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(
    as_pneu_str = "as_did_resource_str",
    borrow = "DIDResourceStr",
    deserialize,
    serialize,
    string_field = "1"
)]
pub struct DIDResource<F: 'static + Fragment + ?Sized>(std::marker::PhantomData<F>, String);

/// Because DIDResource has a type parameter that doesn't require Clone,
/// the standard derive(Clone) doesn't work, because it has incorrect, non-minimal bounds.
/// See https://github.com/rust-lang/rust/issues/41481
/// and https://github.com/rust-lang/rust/issues/26925
impl<F: 'static + Fragment + ?Sized> Clone for DIDResource<F> {
    fn clone(&self) -> Self {
        Self(Default::default(), self.1.clone())
    }
}

impl<F: 'static + Fragment + ?Sized> DIDResource<F> {
    pub fn new(
        host: &str,
        path_o: Option<&str>,
        root_self_hash: &selfhash::KERIHashStr,
        fragment: &F,
    ) -> Result<Self, Error> {
        // TODO: Complete validation of host
        if host.contains(':') || host.contains('/') {
            return Err(Error::Malformed(
                "DIDResource host must not contain ':' or '/'",
            ));
        }
        Self::try_from(format!(
            "did:webplus:{}{}{}:{}#{}",
            host,
            if path_o.is_some() { ":" } else { "" },
            if let Some(path) = path_o { path } else { "" },
            root_self_hash,
            fragment
        ))
    }
    /// Set the root self-hash value to the given value.  This assumes that the new root self-hash has
    /// the same str len as the existing one, and therefore doesn't allocate.
    pub fn set_root_self_hash(&mut self, root_self_hash: &selfhash::KERIHashStr) {
        assert_eq!(self.root_self_hash().len(), root_self_hash.len(), "programmer error: hash function must already be known, producing a known, fixed length for the DID's root self-hash component");
        let end = self.find('#').unwrap();
        assert!(end > self.root_self_hash().len());
        let begin = end - self.root_self_hash().len();
        self.1.replace_range(begin..end, root_self_hash.as_str());
        debug_assert!(
            <DIDResourceStr::<F> as pneutype::Validate>::validate(self.1.as_str()).is_ok()
        );
    }
}

/// This implementation is to allow a `&DIDResource` to function as a `&dyn selfhash::Hash`, which is necessary
/// for the self-hashing functionality.  A DIDResource isn't strictly "a Hash", more like it "has a Hash", but
/// this semantic difference isn't worth doing anything about.
impl<F: 'static + Fragment + ?Sized> selfhash::Hash for DIDResource<F> {
    fn hash_function(&self) -> &'static dyn selfhash::HashFunction {
        self.root_self_hash().hash_function()
    }
    fn as_preferred_hash_format<'s: 'h, 'h>(&'s self) -> selfhash::PreferredHashFormat<'h> {
        Cow::Borrowed(self.root_self_hash()).into()
    }
}
