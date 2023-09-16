use crate::{DIDURIComponents, DIDWebplusWithFragment, Error, Fragment};

#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, PartialEq, serde_with::SerializeDisplay,
)]
pub struct DIDWebplus {
    pub host: String,
    pub self_signature: selfsign::KERISignature<'static>,
}

impl DIDWebplus {
    pub fn with_fragment<F: Fragment>(&self, fragment: F) -> DIDWebplusWithFragment<F> {
        DIDWebplusWithFragment {
            host: self.host.clone(),
            self_signature: self.self_signature.clone(),
            fragment: fragment.into(),
        }
    }
}

impl std::fmt::Display for DIDWebplus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:webplus:{}:{}", self.host, self.self_signature)
    }
}

impl std::str::FromStr for DIDWebplus {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_uri_components = DIDURIComponents::try_from(s)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        let host = did_uri_components.host.to_string();
        let self_signature = selfsign::KERISignature::from_str(did_uri_components.path)?;
        Ok(Self {
            host,
            self_signature,
        })
    }
}
