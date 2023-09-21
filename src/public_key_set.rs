/// This is a stripped down version of the key material for a DID document, without
/// all the ridiculous JSON-brained cruft.
#[derive(Clone, Debug)]
pub struct PublicKeySet<V: Clone + std::fmt::Debug> {
    pub authentication_v: Vec<V>,
    pub assertion_method_v: Vec<V>,
    pub key_agreement_v: Vec<V>,
    pub capability_invocation_v: Vec<V>,
    pub capability_delegation_v: Vec<V>,
}

impl<V: Clone + std::fmt::Debug> PublicKeySet<V> {
    pub fn iter(&self) -> impl Iterator<Item = &V> {
        self.authentication_v
            .iter()
            .chain(self.assertion_method_v.iter())
            .chain(self.key_agreement_v.iter())
            .chain(self.capability_invocation_v.iter())
            .chain(self.capability_delegation_v.iter())
    }
}
