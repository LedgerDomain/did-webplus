use crate::{
    DIDFragment, DIDFullyQualifiedStr, DIDResource, DIDWebplusURIComponents, Error, Fragment,
};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr, serde::Serialize)]
#[pneu_str(deserialize, str_field = "1")]
#[repr(transparent)]
pub struct DIDResourceFullyQualifiedStr<F: 'static + Fragment>(std::marker::PhantomData<F>, str);

impl<F: 'static + Fragment> DIDResourceFullyQualifiedStr<F> {
    pub fn without_query(&self) -> DIDResource<F> {
        DIDResource::new(
            self.host(),
            self.path_o(),
            &self.self_hash(),
            &self.fragment(),
        )
        .expect("programmer error")
    }
    pub fn without_fragment(&self) -> &DIDFullyQualifiedStr {
        DIDFullyQualifiedStr::new_ref(self.1.split_once('#').unwrap().0).expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
    }
    fn uri_components(&self) -> DIDWebplusURIComponents {
        DIDWebplusURIComponents::try_from(self.as_str()).expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
    }
    /// Host of the VDR that acts as the authority/origin for this DID.
    pub fn host(&self) -> &str {
        self.uri_components().host
    }
    /// This is everything between the host and the self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.uri_components().path_o
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn self_hash(&self) -> &selfhash::KERIHashStr {
        self.uri_components().self_hash
    }
    pub fn query_self_hash(&self) -> &selfhash::KERIHashStr {
        self.uri_components().query_self_hash_o.expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
    }
    pub fn query_version_id(&self) -> u32 {
        self.uri_components().query_version_id_o.expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
    }
    /// This is the fragment portion of the DID URI, which is typically a key ID, but could refer to another
    /// resource within the DID document.
    // TODO: Make this return a reference once DIDFragmentStr is implemented
    pub fn fragment(&self) -> DIDFragment<F> {
        DIDFragment::<F>::from_str_without_hash_char(self.uri_components().fragment_o.expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")).expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
    }
}

impl<F: 'static + Fragment> pneutype::Validate for DIDResourceFullyQualifiedStr<F> {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let did_webplus_uri_components = DIDWebplusURIComponents::try_from(data)?;
        if !did_webplus_uri_components.has_query() {
            return Err(Error::Malformed("DID query is missing"));
        }
        if !did_webplus_uri_components.has_fragment() {
            return Err(Error::Malformed("DID fragment is missing"));
        }
        DIDFragment::<F>::from_str_without_hash_char(
            did_webplus_uri_components.fragment_o.unwrap(),
        )?;
        Ok(())
    }
}
