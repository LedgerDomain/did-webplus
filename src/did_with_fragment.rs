use crate::{DIDFragment, DIDURIComponents, DIDWithQueryAndFragment, Error, Fragment, DID};

#[deprecated = "Use DIDWithFragment instead"]
pub type DIDWebplusWithFragment<F> = DIDWithFragment<F>;

#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, PartialEq, serde_with::SerializeDisplay,
)]
pub struct DIDWithFragment<F: Fragment> {
    pub host: String,
    pub self_hash: selfhash::KERIHash<'static>,
    pub fragment: DIDFragment<F>,
}

impl<F: Fragment> DIDWithFragment<F> {
    pub fn without_fragment(&self) -> DID {
        DID {
            host: self.host.clone(),
            self_hash: self.self_hash.clone(),
        }
    }
    pub fn with_query(&self, query: String) -> DIDWithQueryAndFragment<F> {
        DIDWithQueryAndFragment {
            host: self.host.clone(),
            self_hash: self.self_hash.clone(),
            query,
            fragment: self.fragment.clone(),
        }
    }
}

impl<F: Fragment> std::fmt::Display for DIDWithFragment<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note that the fragment includes the leading '#' when it is displayed.
        write!(
            f,
            "did:webplus:{}:{}{}",
            self.host, self.self_hash, self.fragment
        )
    }
}

impl<F: Fragment> std::str::FromStr for DIDWithFragment<F> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_uri_components = DIDURIComponents::try_from(s)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        let host = did_uri_components.host.to_string();
        let self_hash = selfhash::KERIHash::from_str(did_uri_components.path)?;
        if did_uri_components.fragment_o.is_none() {
            return Err(Error::Malformed("DID fragment is missing"));
        }
        let fragment = DIDFragment::from_str_without_hash(did_uri_components.fragment_o.unwrap())?;
        Ok(Self {
            host,
            self_hash,
            fragment,
        })
    }
}
