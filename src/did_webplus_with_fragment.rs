use crate::{
    said_placeholder, said_placeholder_for_uri, DIDURIComponents, DIDWebplus,
    DIDWebplusWithQueryAndFragment, Error, SAID_HASH_FUNCTION_CODE,
};

// A base DID with method "webplus" having fragment but no query params.
#[derive(
    Clone,
    Debug,
    derive_more::Deref,
    serde::Deserialize,
    derive_more::Display,
    Eq,
    derive_more::Into,
    PartialEq,
    serde::Serialize,
)]
pub struct DIDWebplusWithFragment(pub(crate) String);

impl DIDWebplusWithFragment {
    pub fn with_host_and_fragment(host: &str, fragment: &str) -> Result<Self, Error> {
        Self::try_from(format!(
            "did:webplus:{}:{}#{}",
            host,
            said_placeholder_for_uri(&SAID_HASH_FUNCTION_CODE),
            fragment
        ))
    }
    pub fn with_host_and_said_and_fragment(
        host: &str,
        said: &str,
        fragment: &str,
    ) -> Result<Self, Error> {
        use said::sad::DerivationCode;
        if said.len() != SAID_HASH_FUNCTION_CODE.full_size() {
            return Err(Error::Malformed(
                "SAID length does not match hash function code 'full_size' value",
            ));
        }
        Self::try_from(format!("did:webplus:{}:{}#{}", host, said, fragment))
    }
    pub fn components(&self) -> DIDURIComponents {
        DIDURIComponents::try_from(self.as_str())
            .expect("programmer error: should be valid by construction")
    }
    pub fn into_string(self) -> String {
        self.0
    }
    pub fn with_query(&self, query: &str) -> Result<DIDWebplusWithQueryAndFragment, Error> {
        let did_uri_components = DIDURIComponents::try_from(self.as_str()).unwrap();
        DIDWebplusWithQueryAndFragment::try_from(format!(
            "did:{}:{}:{}?{}#{}",
            did_uri_components.method,
            did_uri_components.host,
            did_uri_components.path,
            query,
            did_uri_components.fragment_o.unwrap(),
        ))
    }
    pub fn without_fragment(&self) -> DIDWebplus {
        let did_uri_components = DIDURIComponents::try_from(self.as_str()).unwrap();
        DIDWebplus(format!(
            "did:{}:{}:{}",
            did_uri_components.method, did_uri_components.host, did_uri_components.path,
        ))
    }
    pub fn said_derivation_value(
        &self,
        hash_function_code: &said::derivation::HashFunctionCode,
        said_o: Option<&str>,
    ) -> Self {
        let did_uri_components = DIDURIComponents::try_from(self.as_str()).unwrap();
        use said::sad::DerivationCode;
        if let Some(said) = said_o {
            assert_eq!(
                said.len(),
                hash_function_code.full_size(),
                "programmer error: SAID length does not match hash function code 'full_size' value"
            );
            Self(format!(
                "did:{}:{}:{}#{}",
                did_uri_components.method,
                did_uri_components.host,
                said,
                did_uri_components.fragment_o.unwrap()
            ))
        } else {
            Self(format!(
                "did:{}:{}:{}#{}",
                did_uri_components.method,
                did_uri_components.host,
                said_placeholder(hash_function_code),
                did_uri_components.fragment_o.unwrap()
            ))
        }
    }
}

impl said::sad::SAD for DIDWebplusWithFragment {
    fn compute_digest(&mut self) {
        let with_placeholder = self.said_derivation_value(&SAID_HASH_FUNCTION_CODE, None);
        let said = said::derivation::HashFunction::from(SAID_HASH_FUNCTION_CODE)
            .derive(with_placeholder.as_bytes());

        let with_said =
            self.said_derivation_value(&SAID_HASH_FUNCTION_CODE, Some(said.to_string().as_str()));
        *self = with_said;
    }
    fn derivation_data(&self) -> Vec<u8> {
        self.said_derivation_value(&SAID_HASH_FUNCTION_CODE, None)
            .into_string()
            .into_bytes()
    }
}

impl TryFrom<String> for DIDWebplusWithFragment {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let did_url_components = DIDURIComponents::try_from(value.as_str())?;
        if did_url_components.method != "webplus" {
            return Err(Error::Malformed(
                "DIDWebplusWithFragment expected method 'webplus'",
            ));
        }
        if did_url_components.query_o.is_some() {
            return Err(Error::Malformed(
                "DIDWebplusWithFragment encountered unexpected query params",
            ));
        }
        if did_url_components.fragment_o.is_none() {
            return Err(Error::Malformed("DIDWebplusWithFragment expected fragment"));
        }
        Ok(Self(value.into()))
    }
}
