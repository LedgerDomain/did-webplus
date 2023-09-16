use crate::{DIDURIComponents, Error};

#[derive(Debug, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
pub struct DIDWebplusWithQuery {
    pub host: String,
    pub self_signature: selfsign::KERISignature<'static>,
    pub query: String,
}

impl std::fmt::Display for DIDWebplusWithQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "did:webplus:{}:{}?{}",
            self.host, self.self_signature, self.query
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
        let self_signature = selfsign::KERISignature::from_str(did_uri_components.path)?;
        if did_uri_components.query_o.is_none() {
            return Err(Error::Malformed("DID query is missing"));
        }
        let query = did_uri_components.query_o.unwrap().to_string();
        Ok(Self {
            host,
            self_signature,
            query,
        })
    }
}
