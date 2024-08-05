use crate::{
    DIDFragment, DIDResourceFullyQualified, DIDStr, DIDWebplusURIComponents, Error, Fragment,
};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr, serde::Serialize)]
#[pneu_str(deserialize, str_field = "1")]
#[repr(transparent)]
pub struct DIDResourceStr<F: 'static + Fragment>(std::marker::PhantomData<F>, str);

impl<F: 'static + Fragment> DIDResourceStr<F> {
    pub fn did(&self) -> &DIDStr {
        let (did, _query_params) = self.1.split_once('#').expect("programmer error: this should not fail due to guarantees in construction of DIDResource");
        DIDStr::new_ref(did).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
    pub fn with_queries(
        &self,
        query_self_hash: &selfhash::KERIHashStr,
        query_version_id: u32,
    ) -> DIDResourceFullyQualified<F> {
        DIDResourceFullyQualified::new(
            self.host(),
            self.path_o(),
            self.self_hash(),
            query_self_hash,
            query_version_id,
            self.fragment(),
        ).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
    fn uri_components(&self) -> DIDWebplusURIComponents {
        DIDWebplusURIComponents::try_from(self.as_str()).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
    /// Host of the VDR that acts as the authority/origin for this DID.
    pub fn host(&self) -> &str {
        self.uri_components().host
    }
    /// This is everything between the host and the self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.uri_components().path_o
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn self_hash(&self) -> &selfhash::KERIHashStr {
        self.uri_components().self_hash
    }
    /// This is the fragment portion of the DID URI, which is typically a key ID, but could refer to another
    /// resource within the DID document.
    // TODO: Make DIDFragmentStr and use it here
    pub fn fragment(&self) -> DIDFragment<F> {
        DIDFragment::<F>::from_str_without_hash_char(self.uri_components().fragment_o.expect("programmer error: this should not fail due to guarantees in construction of DIDResource")).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
}

impl<F: 'static + Fragment> pneutype::Validate for DIDResourceStr<F> {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let did_webplus_uri_components = DIDWebplusURIComponents::try_from(data)?;
        if did_webplus_uri_components.has_query() {
            return Err(Error::Malformed("DIDResource must not have a query"));
        }
        if !did_webplus_uri_components.has_fragment() {
            return Err(Error::Malformed("DIDResource must have a fragment"));
        }
        // TODO: Make a version of this that doesn't allocate.  This would be trivial if DIDFragment gets PneuStr'ed
        DIDFragment::<F>::from_str_without_hash_char(
            did_webplus_uri_components.fragment_o.unwrap(),
        )?;
        Ok(())
    }
}
