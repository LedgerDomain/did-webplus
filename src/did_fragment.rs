use crate::Error;

pub trait Fragment: Clone + std::fmt::Debug + std::fmt::Display + std::str::FromStr {}

impl<F: Clone + std::fmt::Debug + std::fmt::Display + std::str::FromStr> Fragment for F {}

#[deprecated = "Use DIDFragment instead"]
pub type DIDWebplusFragment<F> = DIDFragment<F>;

// This is meant to be the did:webplus-specific relative DID URL.  F is the data type meant to represent
// the content after the '#' portion of the DID URI.  Usually this is a key id, but it could refer to
// another kind of resource, such as a service endpoint.
#[derive(
    Clone,
    Debug,
    derive_more::Deref,
    serde_with::DeserializeFromStr,
    Eq,
    PartialEq,
    serde_with::SerializeDisplay,
)]
pub struct DIDFragment<F>(F);

impl<F: Fragment> DIDFragment<F> {
    pub fn from_str_without_hash(s: &str) -> Result<Self, Error> {
        if s.starts_with('#') {
            return Err(Error::Malformed(
                "DIDFragment::from_str_without_hash expected string to not start with '#'",
            ));
        }
        Ok(Self(
            F::from_str(s).map_err(|_| Error::Malformed("Malformed DIDFragment"))?,
        ))
    }
}

impl<F: Fragment> std::fmt::Display for DIDFragment<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

impl<F: Fragment> From<F> for DIDFragment<F> {
    fn from(fragment: F) -> Self {
        Self(fragment)
    }
}

impl<F: Fragment> std::str::FromStr for DIDFragment<F> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('#') {
            return Err(Error::Malformed("DIDFragment must start with '#'"));
        }
        let after_hash = &s[1..];
        Ok(Self(
            F::from_str(after_hash).map_err(|_| Error::Malformed("invalid fragment"))?,
        ))
    }
}

impl<F: Fragment + std::hash::Hash> std::hash::Hash for DIDFragment<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
