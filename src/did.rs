use crate::{DIDURIComponents, DIDWithFragment, DIDWithQuery, Error, Fragment};

#[deprecated = "Use DID instead"]
pub type DIDWebplus = DID;

#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, PartialEq, Hash, serde_with::SerializeDisplay,
)]
pub struct DID {
    pub host: String,
    // TODO: Add pre-self-signature path components
    pub self_hash: selfhash::KERIHash<'static>,
}

impl DID {
    pub fn with_query(&self, query: String) -> DIDWithQuery {
        DIDWithQuery {
            host: self.host.clone(),
            self_hash: self.self_hash.clone(),
            query,
        }
    }
    pub fn with_fragment<F: Fragment>(&self, fragment: F) -> DIDWithFragment<F> {
        DIDWithFragment {
            host: self.host.clone(),
            self_hash: self.self_hash.clone(),
            fragment: fragment.into(),
        }
    }
}

impl std::fmt::Display for DID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:webplus:{}:{}", self.host, self.self_hash)
    }
}

impl std::str::FromStr for DID {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_uri_components = DIDURIComponents::try_from(s)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        let host = did_uri_components.host.to_string();
        let self_hash = selfhash::KERIHash::from_str(did_uri_components.path)?;
        Ok(Self { host, self_hash })
    }
}
