use crate::{DIDStr, DIDURIComponents, DIDURILocatorComponents, Error};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_did_str", borrow = "DIDStr", deserialize, serialize)]
pub struct DID(String);

impl DID {
    /// Construct a DID with the given hostname, port, path, and self-hash.
    pub fn new(
        hostname: &str,
        port_o: Option<u16>,
        path_o: Option<&str>,
        root_self_hash: &mbx::MBHashStr,
    ) -> Result<Self, Error> {
        let did_uri_components = DIDURIComponents {
            locator: DIDURILocatorComponents {
                hostname,
                port_o,
                path: if let Some(path) = path_o { path } else { "/" },
            },
            root_self_hash,
            query_self_hash_o: None,
            query_version_id_o: None,
            relative_resource_o: None,
            fragment_o: None,
        };
        let s = did_uri_components.to_string();
        Self::try_from(s)
    }
    /// Parse (the equivalent of) a resolution URL to produce a DID.
    pub fn from_resolution_url(
        hostname: &str,
        port_o: Option<u16>,
        path: &str,
    ) -> Result<Self, Error> {
        if !path.starts_with('/') {
            return Err(Error::Malformed("resolution URL path must start with '/'"));
        }
        if !path.ends_with("/did.json") {
            return Err(Error::Malformed(
                "resolution URL path must end with '/did.json'",
            ));
        }
        let path_and_root_self_hash_str = path.strip_suffix("/did.json").unwrap();
        if let Some(path_end_slash_index) = path_and_root_self_hash_str.rfind('/') {
            let path = &path_and_root_self_hash_str[..path_end_slash_index + 1];
            let root_self_hash_str = &path_and_root_self_hash_str[path_end_slash_index + 1..];
            let root_self_hash = mbx::MBHashStr::new_ref(root_self_hash_str)?;
            Self::new(hostname, port_o, Some(path), root_self_hash)
        } else {
            Err(Error::Malformed(
                "resolution URL path must contain a '/' character before the root self-hash",
            ))
        }
    }
    /// Parse a did-documents.jsonl resolution URL (e.g. "https://example.com/<root-self-hash>/did-documents.jsonl")
    /// to produce a DID (in this case, "did:webplus:example.com:<root-self-hash>").
    pub fn from_did_documents_jsonl_resolution_url(
        hostname: &str,
        port_o: Option<u16>,
        path: &str,
    ) -> Result<Self, Error> {
        if !path.starts_with('/') {
            return Err(Error::Malformed("resolution URL path must start with '/'"));
        }
        if !path.ends_with("/did-documents.jsonl") {
            return Err(Error::Malformed(
                "did-documents.jsonl resolution URL path must end with 'did-documents.jsonl'",
            ));
        }
        let path_and_root_self_hash_str = path.strip_suffix("/did-documents.jsonl").unwrap();
        let path_end_slash_index = path_and_root_self_hash_str.rfind('/').ok_or_else(|| {
            Error::Malformed(
                "resolution URL path must contain a '/' character before the root self-hash",
            )
        })?;
        let path = &path_and_root_self_hash_str[..path_end_slash_index + 1];
        let root_self_hash_str = &path_and_root_self_hash_str[path_end_slash_index + 1..];
        let root_self_hash = mbx::MBHashStr::new_ref(root_self_hash_str)?;
        Self::new(hostname, port_o, Some(path), root_self_hash)
    }
    /// Set the root self hash value to the given value.
    pub fn set_root_self_hash(&mut self, root_self_hash: &mbx::MBHashStr) {
        // Strip off the root self_hash portion, not including the '/' delimiter before it.
        self.0.truncate(self.0.rfind('/').unwrap() + 1);
        self.0.push_str(root_self_hash.as_str());
        use pneutype::Validate;
        debug_assert!(
            DIDStr::validate(self.0.as_str()).is_ok(),
            "programmer error"
        );
    }
}
