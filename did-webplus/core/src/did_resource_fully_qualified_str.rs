use crate::{
    DIDFullyQualifiedStr, DIDResource, DIDURIComponents, Error, Fragment, RelativeResourceStr,
};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[pneu_str(deserialize, serialize, str_field = "1")]
#[repr(transparent)]
pub struct DIDResourceFullyQualifiedStr<F: 'static + Fragment + ?Sized>(
    std::marker::PhantomData<F>,
    str,
);

impl<F: 'static + Fragment + ?Sized> DIDResourceFullyQualifiedStr<F> {
    pub fn without_query(&self) -> DIDResource<F> {
        DIDResource::new(
            self.hostname(),
            self.port_o(),
            self.path_o(),
            self.root_self_hash(),
            self.fragment(),
        )
        .expect("programmer error")
    }
    pub fn without_fragment(&self) -> &DIDFullyQualifiedStr {
        DIDFullyQualifiedStr::new_ref(self.1.split_once('#').unwrap().0).expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
    }
    fn uri_components(&self) -> DIDURIComponents {
        DIDURIComponents::try_from(self.as_str()).expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
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
    /// This is everything between the host (host is hostname and optional port number) and the root self_hash,
    /// not including the leading and trailing colons.  In particular, if the path is empty, this will be None.
    /// Another example is "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz#0"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.uri_components().path_o
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn root_self_hash(&self) -> &mbx::MBHashStr {
        self.uri_components().root_self_hash
    }
    pub fn query_self_hash(&self) -> &mbx::MBHashStr {
        self.uri_components().query_self_hash_o.expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
    }
    pub fn query_version_id(&self) -> u32 {
        self.uri_components().query_version_id_o.expect("programmer error: this should not fail due to guarantees in construction of DIDResourceFullyQualified")
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
    /// This is the fragment portion of the DID URI, which is typically a key ID, but could refer to another
    /// resource within the DID document.
    pub fn fragment(&self) -> &F {
        F::new_ref(self.uri_components().fragment_o.unwrap()).unwrap()
    }
}

impl<F: 'static + Fragment + ?Sized> pneutype::Validate for DIDResourceFullyQualifiedStr<F> {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let did_uri_components = DIDURIComponents::try_from(data)?;
        if !did_uri_components.has_query() {
            return Err(Error::Malformed("DID query is missing"));
        }
        if !did_uri_components.has_fragment() {
            return Err(Error::Malformed("DID fragment is missing"));
        }
        <F as pneutype::Validate>::validate(did_uri_components.fragment_o.unwrap())
            .map_err(|_| Error::Malformed("DID fragment is malformed"))?;
        Ok(())
    }
}
