use crate::Error;

pub trait Fragment: Clone + std::fmt::Debug + std::fmt::Display + std::str::FromStr {}

impl<F: Clone + std::fmt::Debug + std::fmt::Display + std::str::FromStr> Fragment for F {}

// This is meant to be the DIDWebplus-specific relative DID URL.  F is the data type meant to represent
// the content after the '#' portion of the DID URI.
#[derive(
    Clone,
    Debug,
    derive_more::Deref,
    serde_with::DeserializeFromStr,
    Eq,
    PartialEq,
    serde_with::SerializeDisplay,
)]
pub struct DIDWebplusFragment<F>(F);

impl<F: Fragment> std::fmt::Display for DIDWebplusFragment<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

impl<F: Fragment> From<F> for DIDWebplusFragment<F> {
    fn from(fragment: F) -> Self {
        Self(fragment)
    }
}

impl<F: Fragment> std::str::FromStr for DIDWebplusFragment<F> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('#') {
            return Err(Error::Malformed("DIDWebplusFragment must start with '#'"));
        }
        let after_hash = &s[1..];
        Ok(Self(
            F::from_str(after_hash).map_err(|_| Error::Malformed("invalid fragment"))?,
        ))
    }
}

impl<F: Fragment + std::hash::Hash> std::hash::Hash for DIDWebplusFragment<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
