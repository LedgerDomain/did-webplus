use crate::{
    DIDFragment, DIDResourceFullyQualified, DIDStr, DIDWebplusURIComponents, Error, Fragment,
};
use std::str::FromStr;

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr, serde::Serialize)]
#[pneu_str(deserialize)]
#[repr(transparent)]
pub struct DIDFullyQualifiedStr(str);

impl DIDFullyQualifiedStr {
    /// Produces the DIDStr that has the query portion stripped off (the '?' char and everything after it).
    pub fn did(&self) -> &DIDStr {
        let (did, _query_params) = self.0.split_once('?').expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified");
        DIDStr::new_ref(did).expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
    pub fn with_fragment<F: Fragment>(&self, fragment: F) -> DIDResourceFullyQualified<F> {
        DIDResourceFullyQualified::new(
            self.host(),
            self.path_o(),
            self.root_self_hash(),
            self.query_self_hash(),
            self.query_version_id(),
            DIDFragment::from(fragment),
        ).expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
    fn uri_components(&self) -> DIDWebplusURIComponents {
        DIDWebplusURIComponents::try_from(self.as_str()).expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
    /// Host of the VDR that acts as the authority/origin for this DID.
    pub fn host(&self) -> &str {
        self.uri_components().host
    }
    /// This is everything between the host and the root self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.uri_components().path_o
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn root_self_hash(&self) -> &selfhash::KERIHashStr {
        self.uri_components().root_self_hash
    }
    pub fn query_self_hash(&self) -> &selfhash::KERIHashStr {
        self.uri_components().query_self_hash_o.expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
    pub fn query_version_id(&self) -> u32 {
        self.uri_components().query_version_id_o.expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
    /// Produce the URL that addresses the specified DID document for this DID.  Note that the selfHash
    /// query param is used (and not the versionId query param) in the resolution URL.
    pub fn resolution_url(&self, scheme: &'static str) -> String {
        // Form the base URL.
        let mut url = format!("{}://{}/", scheme, self.host());
        if let Some(path) = self.path_o() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.root_self_hash().as_str());
        url.push_str("/did");

        // Append query param portion of filename.  We only use the selfHash to form the URL.
        // Note that %3D is the URL-encoding of '='
        url.push_str("/selfHash/");
        url.push_str(self.query_self_hash().as_str());
        url.push_str(".json");

        url
    }
}

impl pneutype::Validate for DIDFullyQualifiedStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let did_webplus_uri_components = DIDWebplusURIComponents::try_from(data)?;
        if did_webplus_uri_components.query_self_hash_o.is_none()
            || did_webplus_uri_components.query_version_id_o.is_none()
        {
            return Err(Error::Malformed(
                "DIDFullyQualified must have both a selfHash and versionId query",
            ));
        }
        if did_webplus_uri_components.has_fragment() {
            return Err(Error::Malformed(
                "DIDFullyQualified must not have a fragment",
            ));
        }
        Ok(())
    }
}

pub(crate) fn parse_did_query_params(
    query_params: &str,
) -> Result<(Option<&selfhash::KERIHashStr>, Option<u32>), Error> {
    let (self_hash_str_o, version_id_str_o) =
        if let Some((first_query, rest)) = query_params.split_once('&') {
            if rest.contains('&') {
                return Err(Error::Malformed(
                    "DID query params may only specify selfHash and/or versionId",
                ));
            }
            let second_query = rest;
            if !first_query.starts_with("selfHash=") || !second_query.starts_with("versionId=") {
                return Err(Error::Malformed(
                "DID query params must specify selfHash before versionId if they're both specified",
            ));
            }
            let self_hash_str = first_query.strip_prefix("selfHash=").unwrap();
            let version_id_str = second_query.strip_prefix("versionId=").unwrap();
            (Some(self_hash_str), Some(version_id_str))
        } else {
            if query_params.starts_with("selfHash=") {
                let self_hash_str = query_params.strip_prefix("selfHash=").unwrap();
                (Some(self_hash_str), None)
            } else if query_params.starts_with("versionId=") {
                let version_id_str = query_params.strip_prefix("versionId=").unwrap();
                (None, Some(version_id_str))
            } else {
                return Err(Error::Malformed("Unrecognized DID query param"));
            }
        };

    let query_self_hash_o = self_hash_str_o
        .map(selfhash::KERIHashStr::new_ref)
        .transpose()?;
    let query_version_id_o = version_id_str_o
        .map(<u32 as FromStr>::from_str)
        .transpose()
        .map_err(|_| Error::Malformed("Unparseable versionId in DID query param"))?;

    Ok((query_self_hash_o, query_version_id_o))
}
