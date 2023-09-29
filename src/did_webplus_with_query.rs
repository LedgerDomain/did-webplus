use crate::{DIDURIComponents, DIDWebplusWithQueryAndFragment, Error, Fragment};

#[derive(Debug, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
pub struct DIDWebplusWithQuery {
    pub host: String,
    pub self_hash: selfhash::KERIHash<'static>,
    pub query: String,
}

impl DIDWebplusWithQuery {
    pub fn without_query(&self) -> crate::DIDWebplus {
        crate::DIDWebplus {
            host: self.host.clone(),
            self_hash: self.self_hash.clone(),
        }
    }
    pub fn with_fragment<F: Fragment>(&self, fragment: F) -> DIDWebplusWithQueryAndFragment<F> {
        DIDWebplusWithQueryAndFragment {
            host: self.host.clone(),
            self_hash: self.self_hash.clone(),
            query: self.query.clone(),
            fragment: fragment.into(),
        }
    }
}

impl std::fmt::Display for DIDWebplusWithQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "did:webplus:{}:{}?{}",
            self.host, self.self_hash, self.query
        )
    }
}

impl std::str::FromStr for DIDWebplusWithQuery {
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
        Ok(Self {
            host,
            self_hash,
            query,
        })
    }
}
