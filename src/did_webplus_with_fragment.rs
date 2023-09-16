use crate::{
    DIDURIComponents, DIDWebplus, DIDWebplusFragment, DIDWebplusWithQueryAndFragment, Error,
    Fragment,
};

#[derive(
    Clone, Debug, serde_with::DeserializeFromStr, Eq, PartialEq, serde_with::SerializeDisplay,
)]
pub struct DIDWebplusWithFragment<F: Fragment> {
    pub host: String,
    pub self_signature: selfsign::KERISignature<'static>,
    pub fragment: DIDWebplusFragment<F>,
}

impl<F: Fragment> DIDWebplusWithFragment<F> {
    pub fn without_fragment(&self) -> DIDWebplus {
        DIDWebplus {
            host: self.host.clone(),
            self_signature: self.self_signature.clone(),
        }
    }
    pub fn with_query(&self, query: String) -> DIDWebplusWithQueryAndFragment<F> {
        DIDWebplusWithQueryAndFragment {
            host: self.host.clone(),
            self_signature: self.self_signature.clone(),
            query,
            fragment: self.fragment.clone(),
        }
    }
}

impl<F: Fragment> std::fmt::Display for DIDWebplusWithFragment<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note that the fragment includes the leading '#' when it is displayed.
        write!(
            f,
            "did:webplus:{}:{}{}",
            self.host, self.self_signature, self.fragment
        )
    }
}

impl<F: Fragment> std::str::FromStr for DIDWebplusWithFragment<F> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_uri_components = DIDURIComponents::try_from(s)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        let host = did_uri_components.host.to_string();
        let self_signature = selfsign::KERISignature::from_str(did_uri_components.path)?;
        if did_uri_components.fragment_o.is_none() {
            return Err(Error::Malformed("DID fragment is missing"));
        }
        let fragment = DIDWebplusFragment::from_str(did_uri_components.fragment_o.unwrap())?;
        Ok(Self {
            host,
            self_signature,
            fragment,
        })
    }
}
