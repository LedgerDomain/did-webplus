use crate::{
    DIDFullyQualified, DIDResource, DIDURIComponents, DIDWithQuery, Error, Fragment,
    HTTPSchemeOverride,
};
use std::fmt::Write;

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[pneu_str(deserialize, serialize)]
#[repr(transparent)]
pub struct DIDStr(str);

impl DIDStr {
    /// Produces the DIDFullyQualified of the root DID document of this DID, which has
    /// query params selfHash and versionId set to the root DID document self-hash and version ID.
    pub fn root_did_document_fully_qualified(&self) -> DIDFullyQualified {
        DIDFullyQualified::try_from(format!(
            "{}?selfHash={}&versionId=0",
            self,
            self.root_self_hash()
        ))
        .expect("programmer error")
    }
    fn uri_components(&self) -> DIDURIComponents {
        DIDURIComponents::try_from(self.as_str()).expect(
            "programmer error: this should not fail due to guarantees in construction of DID",
        )
    }
    /// This gives the hostname of the VDR that acts as the authority/origin for this DID.
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
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ" which will have path_o
    /// of Some("foo:bar:baz").
    pub fn path_o(&self) -> Option<&str> {
        self.uri_components().path_o
    }
    /// This is the self-hash (as a MBHashStr) of the root DID document, which is what makes it a unique ID.
    pub fn root_self_hash(&self) -> &mbx::MBHashStr {
        self.uri_components().root_self_hash
    }
    pub fn with_query_self_hash(&self, query_self_hash: &mbx::MBHashStr) -> DIDWithQuery {
        DIDWithQuery::new(
            self.hostname(),
            self.port_o(),
            self.path_o(),
            self.root_self_hash(),
            Some(query_self_hash),
            None,
        )
        .expect("programmer error")
    }
    pub fn with_query_version_id(&self, query_version_id: u32) -> DIDWithQuery {
        DIDWithQuery::new(
            self.hostname(),
            self.port_o(),
            self.path_o(),
            self.root_self_hash(),
            None,
            Some(query_version_id),
        )
        .expect("programmer error")
    }
    pub fn with_queries(
        &self,
        query_self_hash: &mbx::MBHashStr,
        query_version_id: u32,
    ) -> DIDFullyQualified {
        DIDFullyQualified::new(
            self.hostname(),
            self.port_o(),
            self.path_o(),
            self.root_self_hash(),
            query_self_hash,
            query_version_id,
        )
        .expect("programmer error")
    }
    pub fn with_fragment<F: Fragment + ?Sized>(&self, fragment: &F) -> DIDResource<F> {
        DIDResource::new(
            self.hostname(),
            self.port_o(),
            self.path_o(),
            self.root_self_hash(),
            fragment,
        )
        .expect("programmer error")
    }
    /// Produce the URL that addresses the latest DID document for this DID.
    pub fn resolution_url(&self, http_scheme_override_o: Option<&HTTPSchemeOverride>) -> String {
        let http_scheme = HTTPSchemeOverride::determine_http_scheme_for_host_from(
            http_scheme_override_o,
            self.hostname(),
        )
        .unwrap();
        let mut url = format!("{}://{}", http_scheme, self.hostname());
        if let Some(port) = self.port_o() {
            url.write_fmt(format_args!(":{}", port)).unwrap();
        }
        url.push('/');
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.root_self_hash().as_str());
        url.push_str("/did.json");
        url
    }
    /// Produce the URL that addresses the did-documents.jsonl file for this DID.
    pub fn resolution_url_for_did_documents_jsonl(
        &self,
        http_scheme_override_o: Option<&HTTPSchemeOverride>,
    ) -> String {
        let http_scheme = HTTPSchemeOverride::determine_http_scheme_for_host_from(
            http_scheme_override_o,
            self.hostname(),
        )
        .unwrap();
        let mut url = format!("{}://{}", http_scheme, self.hostname());
        if let Some(port) = self.port_o() {
            url.write_fmt(format_args!(":{}", port)).unwrap();
        }
        url.push('/');
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.root_self_hash().as_str());
        url.push_str("/did-documents.jsonl");
        url
    }
}

impl pneutype::Validate for DIDStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let did_uri_components = DIDURIComponents::try_from(data)?;
        if did_uri_components.has_query() {
            return Err(Error::Malformed("DID must not have a query"));
        }
        if did_uri_components.has_fragment() {
            return Err(Error::Malformed("DID must not have a fragment"));
        }
        Ok(())
    }
}
