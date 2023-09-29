use crate::{
    DIDURIComponents, DIDWebplusFragment, DIDWebplusWithFragment, DIDWebplusWithQuery, Error,
    Fragment,
};

#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, PartialEq, serde_with::SerializeDisplay,
)]
pub struct DIDWebplusWithQueryAndFragment<F: Fragment> {
    pub host: String,
    pub self_hash: selfhash::KERIHash<'static>,
    pub query: String,
    pub fragment: DIDWebplusFragment<F>,
}

impl<F: Fragment> DIDWebplusWithQueryAndFragment<F> {
    pub fn without_query(&self) -> DIDWebplusWithFragment<F> {
        DIDWebplusWithFragment {
            host: self.host.clone(),
            self_hash: self.self_hash.clone(),
            fragment: self.fragment.clone(),
        }
    }
    pub fn without_fragment(&self) -> DIDWebplusWithQuery {
        DIDWebplusWithQuery {
            host: self.host.clone(),
            self_hash: self.self_hash.clone(),
            query: self.query.clone(),
        }
    }
}

impl<F: Fragment> std::fmt::Display for DIDWebplusWithQueryAndFragment<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note that the fragment includes the leading '#' when it is displayed.
        write!(
            f,
            "did:webplus:{}:{}?{}{}",
            self.host, self.self_hash, self.query, self.fragment
        )
    }
}

impl<F: Fragment> std::str::FromStr for DIDWebplusWithQueryAndFragment<F> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_uri_components = DIDURIComponents::try_from(s)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        let host = did_uri_components.host.to_string();
        let self_hash = selfhash::KERIHash::from_str(did_uri_components.path)?;
        if did_uri_components.query_o.is_none() {
            return Err(Error::Malformed("DID query is missing"));
        }
        let query = did_uri_components.query_o.unwrap().to_string();
        if did_uri_components.fragment_o.is_none() {
            return Err(Error::Malformed("DID fragment is missing"));
        }
        let fragment = DIDWebplusFragment::from_str(did_uri_components.fragment_o.unwrap())?;
        Ok(Self {
            host,
            self_hash,
            query,
            fragment,
        })
    }
}
