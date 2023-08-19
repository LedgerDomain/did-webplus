use crate::{
    said_placeholder_for_uri, DIDURIComponents, DIDWebplus, Error, SAID_HASH_FUNCTION_CODE,
};

// A base DID with method "webplus" and with no query params or fragment.
#[derive(
    Clone,
    Debug,
    derive_more::Deref,
    derive_more::Display,
    derive_more::Into,
    serde::Serialize,
    serde::Deserialize,
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
        Self::try_from(format!("did:webplus:{}:{}:{}", host, said, fragment))
    }
    pub fn into_string(self) -> String {
        self.0
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
            let placeholder = "#".repeat(hash_function_code.full_size());
            Self(format!(
                "did:{}:{}:{}:{}",
                did_uri_components.method,
                did_uri_components.host,
                placeholder,
                did_uri_components.fragment_o.unwrap()
            ))
        }
    }
}

impl said::sad::SAD for DIDWebplusWithFragment {
    fn compute_digest(&mut self) {
        let did_webplus_with_placeholder =
            self.said_derivation_value(&SAID_HASH_FUNCTION_CODE, None);
        let said = said::derivation::HashFunction::from(SAID_HASH_FUNCTION_CODE)
            .derive(did_webplus_with_placeholder.as_bytes());

        let did_webplus_with_said =
            self.said_derivation_value(&SAID_HASH_FUNCTION_CODE, Some(said.to_string().as_str()));
        *self = did_webplus_with_said;
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
