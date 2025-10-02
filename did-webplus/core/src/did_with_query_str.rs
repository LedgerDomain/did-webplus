use crate::{DIDStr, DIDURIComponents, Error, HTTPSchemeOverride};
use std::fmt::Write;

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[pneu_str(deserialize, serialize)]
#[repr(transparent)]
pub struct DIDWithQueryStr(str);

impl DIDWithQueryStr {
    /// Produces the DIDStr that has the query portion stripped off (the '?' char and everything after it).
    pub fn did(&self) -> &DIDStr {
        let (did, _query_params) = self.0.split_once('?').expect("programmer error: this should not fail due to guarantees in construction of DIDWithQuery");
        DIDStr::new_ref(did).expect("programmer error: this should not fail due to guarantees in construction of DIDWithQuery")
    }
    fn uri_components(&self) -> DIDURIComponents {
        DIDURIComponents::try_from(self.as_str()).expect("programmer error: this should not fail due to guarantees in construction of DIDWithQuery")
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
    /// This is everything between the host and the root self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ?abc=xyz"
    /// which will have path_o of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.uri_components().path_o
    }
    /// This is the self-hash of the root DID document, which is what makes it a unique ID.
    pub fn root_self_hash(&self) -> &mbx::MBHashStr {
        self.uri_components().root_self_hash
    }
    /// Returns the query selfHash value if present, otherwise None.
    pub fn query_self_hash_o(&self) -> Option<&mbx::MBHashStr> {
        self.uri_components().query_self_hash_o
    }
    /// Returns the query versionId value if present, otherwise None.
    pub fn query_version_id_o(&self) -> Option<u32> {
        self.uri_components().query_version_id_o
    }

    /// Produce the URL that addresses the specified DID document for this DID.
    /// If both the selfHash and versionId query params are present, the selfHash takes precedence.
    pub fn resolution_url(&self, http_scheme_override_o: Option<&HTTPSchemeOverride>) -> String {
        let http_scheme = HTTPSchemeOverride::determine_http_scheme_for_host_from(
            http_scheme_override_o,
            self.hostname(),
        )
        .unwrap();
        // Form the base URL
        let mut url = format!("{}://{}", http_scheme, self.hostname());
        if let Some(port) = self.port_o() {
            url.push(':');
            url.write_fmt(format_args!("{}", port)).unwrap();
        }
        if let Some(path) = self.path_o().as_deref() {
            url.push('/');
            url.push_str(&path.replace(':', "/"));
        }
        url.push('/');
        url.push_str(self.root_self_hash().as_str());
        url.push_str("/did");

        // Append query param portion of filename.
        match (self.query_self_hash_o(), self.query_version_id_o()) {
            (Some(query_self_hash), _) => {
                // We only use the selfHash to form the URL in this case.
                // Note that %3D is the URL-encoding of '='
                url.push_str("/selfHash/");
                url.push_str(query_self_hash.as_str());
            }
            (None, Some(query_version_id)) => {
                // We use the versionId to form the URL in this case.
                // Note that %3D is the URL-encoding of '='
                url.push_str("/versionId/");
                url.push_str(&query_version_id.to_string());
            }
            (None, None) => {
                // Add nothing.
            }
        }
        url.push_str(".json");

        url
    }
}

impl pneutype::Validate for DIDWithQueryStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let did_uri_components = DIDURIComponents::try_from(data)?;
        if !did_uri_components.has_query() {
            return Err(Error::Malformed(
                "DIDWithQuery must have at least one of selfHash and/or versionId query params specified",
            ));
        }
        if did_uri_components.has_fragment() {
            return Err(Error::Malformed("DIDWithQuery must not have a fragment"));
        }
        Ok(())
    }
}
