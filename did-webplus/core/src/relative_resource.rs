use crate::RelativeResourceStr;

pub trait Fragment: pneutype::PneuStr {}

impl<F: pneutype::PneuStr + ?Sized> Fragment for F {}

/// This is meant to be the did:webplus-specific relative DID URL.  F is the data type meant to represent
/// the content after the '#' portion of the DID URI.  Usually this is a key id, but it could refer to
/// another kind of resource, such as a service endpoint.
#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(
    as_pneu_str = "as_relative_resource_str",
    borrow = "RelativeResourceStr",
    deserialize,
    serialize,
    string_field = "1"
)]
pub struct RelativeResource<F: 'static + Fragment + ?Sized>(std::marker::PhantomData<F>, String);

/// Because RelativeResource has a type parameter that doesn't require Clone,
/// the standard derive(Clone) doesn't work, because it has incorrect, non-minimal bounds.
/// See <https://github.com/rust-lang/rust/issues/41481>
/// and <https://github.com/rust-lang/rust/issues/26925>
impl<F: 'static + Fragment + ?Sized> Clone for RelativeResource<F> {
    fn clone(&self) -> Self {
        Self(Default::default(), self.1.clone())
    }
}

impl<F: 'static + Fragment + ?Sized> RelativeResource<F> {
    pub fn from_fragment(fragment: &F) -> Self {
        Self::try_from(format!("#{}", fragment)).expect("programmer error")
    }
}
