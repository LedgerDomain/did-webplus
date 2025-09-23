use crate::{
    DIDResourceFullyQualified, DIDStr, DIDWebplusURIComponents, Error, Fragment,
    RelativeResourceStr,
};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[pneu_str(deserialize, serialize, str_field = "1")]
#[repr(transparent)]
pub struct DIDResourceStr<F: 'static + Fragment + ?Sized>(std::marker::PhantomData<F>, str);

impl<F: 'static + Fragment + ?Sized> DIDResourceStr<F> {
    pub fn did(&self) -> &DIDStr {
        let (did, _fragment) = self.1.split_once('#').expect("programmer error: this should not fail due to guarantees in construction of DIDResource");
        DIDStr::new_ref(did).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
    pub fn with_queries(
        &self,
        query_self_hash: &mbx::MBHashStr,
        query_version_id: u32,
    ) -> DIDResourceFullyQualified<F> {
        DIDResourceFullyQualified::new(
            self.hostname(),
            self.port_o(),
            self.path_o(),
            self.root_self_hash(),
            query_self_hash,
            query_version_id,
            self.fragment(),
        ).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
    pub fn without_fragment(&self) -> &DIDStr {
        DIDStr::new_ref(self.1.split_once('#').unwrap().0).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
    fn uri_components(&self) -> DIDWebplusURIComponents {
        DIDWebplusURIComponents::try_from(self.as_str()).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
    /// Hostname of the VDR that acts as the authority/origin for this DID.
    pub fn hostname(&self) -> &str {
        self.uri_components().hostname
    }
    /// This gives the port (if specified in the DID) of the VDR that acts as the authority/origin
    /// for this DID, or None if not specified.
    pub fn port_o(&self) -> Option<u16> {
        self.uri_components().port_o
    }
    /// This is everything between the host and the self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ#Dd5KLEikQpGOXARnADIQnzUtvYHer62lXDjTb53f81ZU"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.uri_components().path_o
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn root_self_hash(&self) -> &mbx::MBHashStr {
        self.uri_components().root_self_hash
    }
    /// This is the relative resource portion of the DID URI, which is the '#' char and everything following.
    pub fn relative_resource(&self) -> &RelativeResourceStr<F> {
        RelativeResourceStr::<F>::new_ref(
            self.uri_components()
                .relative_resource_o
                .expect("programmer error"),
        )
        .expect("programmer error")
    }
    pub fn fragment(&self) -> &F {
        F::new_ref(self.uri_components().fragment_o.expect("programmer error"))
            .expect("programmer error")
    }
}

impl<F: 'static + Fragment + ?Sized> pneutype::Validate for DIDResourceStr<F> {
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
        F::validate(did_webplus_uri_components.fragment_o.unwrap())
            .map_err(|_| Error::Malformed("DIDResource fragment is malformed"))?;
        Ok(())
    }
}
