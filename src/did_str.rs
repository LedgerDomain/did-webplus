use selfhash::KERIHash;

use crate::{
    DIDURIComponents, Error, Fragment, ParsedDID, ParsedDIDWithFragment, ParsedDIDWithQuery,
};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr, serde::Serialize)]
#[pneu_str(deserialize)]
#[repr(transparent)]
pub struct DIDStr(str);

impl DIDStr {
    pub fn parsed(&self) -> ParsedDID {
        let did_uri_components =
            DIDURIComponents::try_from(self.as_str()).expect("programmer error");
        let host = did_uri_components.host.to_string();
        let (path_o, self_hash_str) =
            if let Some((path, self_hash_str)) = did_uri_components.path.rsplit_once(':') {
                (Some(path.to_string()), self_hash_str)
            } else {
                (None, did_uri_components.path)
            };
        let self_hash = KERIHash::try_from(self_hash_str).expect("programmer error");
        ParsedDID::new(host, path_o, self_hash).expect("programmer error")
    }
    /// This gives the host of the VDR that acts as the authority/origin for this DID.
    pub fn host(&self) -> &str {
        let did_uri_components =
            DIDURIComponents::try_from(self.as_str()).expect("programmer error");
        did_uri_components.host
    }
    /// This is everything between the host and the self_hash, not including the leading and trailing
    /// colons.  In particular, if the path is empty, this will be None.  Another example is
    /// "did:webplus:foo:bar:baz:EVFp-xj7y-ZhG5YQXhO_WS_E-4yVX69UeTefKAC8G_YQ" which will have path_o
    /// of Some("foo:bar:baz").
    // TODO: Maybe "no path" should just be the empty string to simplify things.
    pub fn path_o(&self) -> Option<&str> {
        let did_uri_components =
            DIDURIComponents::try_from(self.as_str()).expect("programmer error");
        if let Some((path, _self_hash_str)) = did_uri_components.path.rsplit_once(':') {
            Some(path)
        } else {
            None
        }
    }
    /// This is the self-hash (as a &str) of the root DID document, which is what makes it a unique ID.
    fn self_hash_str(&self) -> &str {
        let did_uri_components =
            DIDURIComponents::try_from(self.as_str()).expect("programmer error");
        if let Some((_path, self_hash_str)) = did_uri_components.path.rsplit_once(':') {
            self_hash_str
        } else {
            did_uri_components.path
        }
    }
    /// This is the self-hash (as a KERIHash) of the root DID document, which is what makes it a unique ID.
    pub fn self_hash(&self) -> &selfhash::KERIHashStr {
        selfhash::KERIHashStr::new_ref(self.self_hash_str()).expect("programmer error")
    }
    pub fn with_query_self_hash(&self, query_self_hash: selfhash::KERIHash) -> ParsedDIDWithQuery {
        ParsedDIDWithQuery {
            host: self.host().to_string(),
            path_o: self.path_o().map(|path| path.to_string()),
            self_hash: self.self_hash().to_owned(),
            query_self_hash_o: Some(query_self_hash),
            query_version_id_o: None,
        }
    }
    pub fn with_query_version_id(&self, query_version_id: u32) -> ParsedDIDWithQuery {
        ParsedDIDWithQuery {
            host: self.host().to_string(),
            path_o: self.path_o().map(|path| path.to_string()),
            self_hash: self.self_hash().to_owned(),
            query_self_hash_o: None,
            query_version_id_o: Some(query_version_id),
        }
    }
    pub fn with_queries(
        &self,
        query_self_hash: selfhash::KERIHash,
        query_version_id: u32,
    ) -> ParsedDIDWithQuery {
        ParsedDIDWithQuery {
            host: self.host().to_string(),
            path_o: self.path_o().map(|path| path.to_string()),
            self_hash: self.self_hash().to_owned(),
            query_self_hash_o: Some(query_self_hash),
            query_version_id_o: Some(query_version_id),
        }
    }
    pub fn with_fragment<F: Fragment>(&self, fragment: F) -> ParsedDIDWithFragment<F> {
        ParsedDIDWithFragment::new(
            self.host().to_string(),
            self.path_o().map(|path| path.to_string()),
            self.self_hash().to_owned(),
            fragment.into(),
        )
        .expect("programmer error")
    }
    /// Produce the URL that addresses the latest DID document for this DID.
    pub fn resolution_url(&self, scheme: &'static str) -> String {
        let mut url = format!("{}://{}/", scheme, self.host());
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash_str());
        url.push_str("/did.json");
        url
    }
    /// Produce the URL that addresses the DID document for this DID that has the given self-hash.
    pub fn resolution_url_for_self_hash(
        &self,
        self_hash: &selfhash::KERIHashStr,
        scheme: &'static str,
    ) -> String {
        let mut url = format!("{}://{}/", scheme, self.host());
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash_str());
        url.push_str("/did/selfHash/");
        url.push_str(self_hash.as_str());
        url.push_str(".json");
        url
    }
    /// Produce the URL that addresses the DID document for this DID that has the given version ID.
    pub fn resolution_url_for_version_id(&self, version_id: u32, scheme: &'static str) -> String {
        let mut url = format!("{}://{}/", scheme, self.host());
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash_str());
        url.push_str("/did/versionId/");
        url.push_str(&format!("{}.json", version_id));
        url
    }
    /// Produce the URL that addresses the current DID document metadata for this DID.
    pub fn resolution_url_for_metadata_current(&self, scheme: &'static str) -> String {
        let mut url = format!("{}://{}/", scheme, self.host());
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash_str());
        url.push_str("/did/metadata.json");
        url
    }
    /// Produce the URL that addresses the constant DID document metadata for this DID
    /// (in particular, this includes DID creation timestamp).
    pub fn resolution_url_for_metadata_constant(&self, scheme: &'static str) -> String {
        let mut url = format!("{}://{}/", scheme, self.host());
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash_str());
        url.push_str("/did/metadata/constant.json");
        url
    }
    /// Produce the URL that addresses the idempotent portion of the DID document metadata for
    /// this DID that has the given self-hash.
    pub fn resolution_url_for_metadata_idempotent_for_self_hash(
        &self,
        self_hash: &selfhash::KERIHashStr,
        scheme: &'static str,
    ) -> String {
        let mut url = format!("{}://{}/", scheme, self.host());
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash_str());
        url.push_str("/did/metadata/selfHash/");
        url.push_str(self_hash.as_str());
        url.push_str(".json");
        url
    }
    /// Produce the URL that addresses the idempotent portion of the DID document metadata for this
    /// DID that has the given version ID.
    pub fn resolution_url_for_metadata_idempotent_for_version_id(
        &self,
        version_id: u32,
        scheme: &'static str,
    ) -> String {
        let mut url = format!("{}://{}/", scheme, self.host());
        if let Some(path) = self.path_o().as_deref() {
            url.push_str(&path.replace(':', "/"));
            url.push('/');
        }
        url.push_str(self.self_hash_str());
        url.push_str("/did/metadata/versionId/");
        url.push_str(&format!("{}.json", version_id));
        url
    }
}

impl pneutype::Validate for DIDStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let did_uri_components = DIDURIComponents::try_from(data)?;
        if did_uri_components.method != "webplus" {
            return Err(Error::Malformed("DID method is not 'webplus'"));
        }
        if did_uri_components.query_o.is_some() {
            return Err(Error::Malformed("DID must not have a query"));
        }
        if did_uri_components.fragment_o.is_some() {
            return Err(Error::Malformed("DID must not have a fragment"));
        }
        let (_path_o, self_hash_str) =
            if let Some((path, self_hash_str)) = did_uri_components.path.rsplit_once(':') {
                if path.contains('/') {
                    return Err(Error::Malformed("DID path component must not contain '/'"));
                }
                (Some(path), self_hash_str)
            } else {
                (None, did_uri_components.path)
            };
        // let _path_o = path_o.map(|s| s.into());
        let _self_hash = selfhash::KERIHash::try_from(self_hash_str)?;
        Ok(())
    }
}
