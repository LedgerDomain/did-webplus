use crate::{DIDResourceFullyQualified, DIDStr, DIDURIComponents, Error, Fragment};
use std::str::FromStr;

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[pneu_str(deserialize, serialize)]
#[repr(transparent)]
pub struct DIDFullyQualifiedStr(str);

impl DIDFullyQualifiedStr {
    /// Produces the DIDStr that has the query portion stripped off (the '?' char and everything after it).
    pub fn did(&self) -> &DIDStr {
        let (did, _query_params) = self.0.split_once('?').expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified");
        DIDStr::new_ref(did).expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
    pub fn with_fragment<F: Fragment + ?Sized>(
        &self,
        fragment: &F,
    ) -> DIDResourceFullyQualified<F> {
        DIDResourceFullyQualified::new(
            self.hostname(),
            self.port_o(),
            self.path_o(),
            self.root_self_hash(),
            self.query_self_hash(),
            self.query_version_id(),
            fragment,
        ).expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
    fn uri_components(&self) -> DIDURIComponents<'_> {
        DIDURIComponents::try_from(self.as_str()).expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
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
    /// Another example is "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.uri_components().path_o
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn root_self_hash(&self) -> &mbx::MBHashStr {
        self.uri_components().root_self_hash
    }
    pub fn query_self_hash(&self) -> &mbx::MBHashStr {
        self.uri_components().query_self_hash_o.expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
    pub fn query_version_id(&self) -> u32 {
        self.uri_components().query_version_id_o.expect("programmer error: this should not fail due to guarantees in construction of DIDFullyQualified")
    }
}

impl pneutype::Validate for DIDFullyQualifiedStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let did_uri_components = DIDURIComponents::try_from(data)?;
        if did_uri_components.query_self_hash_o.is_none() {
            return Err(Error::Malformed(
                "DIDFullyQualified must have a selfHash query param".into(),
            ));
        }
        if did_uri_components.query_version_id_o.is_none() {
            return Err(Error::Malformed(
                "DIDFullyQualified must have a versionId query param".into(),
            ));
        }
        if did_uri_components.has_fragment() {
            return Err(Error::Malformed(
                format!(
                    "DIDFullyQualified must not have a fragment, but had fragment: {:?}",
                    did_uri_components.fragment_o.as_ref().unwrap(),
                )
                .into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn parse_did_query_params(
    query_params: &str,
) -> Result<(Option<&mbx::MBHashStr>, Option<u32>), Error> {
    let (self_hash_str_o, version_id_str_o) =
        if let Some((first_query, rest)) = query_params.split_once('&') {
            if rest.contains('&') {
                return Err(Error::Malformed(
                    "DID query params may only specify selfHash and/or versionId".into(),
                ));
            }
            let second_query = rest;
            if !first_query.starts_with("selfHash=") || !second_query.starts_with("versionId=") {
                return Err(Error::Malformed(
                "DID query params must specify selfHash before versionId if they're both specified"
                    .into(),
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
                return Err(Error::Malformed(
                    format!("Unrecognized DID query param(s): {}", query_params).into(),
                ));
            }
        };

    let query_self_hash_o = self_hash_str_o.map(mbx::MBHashStr::new_ref).transpose()?;
    let query_version_id_o = version_id_str_o
        .map(<u32 as FromStr>::from_str)
        .transpose()
        .map_err(|_| {
            Error::Malformed(
                format!(
                    "Unparseable versionId in DID query param: {}",
                    version_id_str_o.unwrap()
                )
                .into(),
            )
        })?;

    Ok((query_self_hash_o, query_version_id_o))
}
