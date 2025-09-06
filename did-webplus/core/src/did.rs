use crate::{DIDStr, DIDWebplusURIComponents, Error};
use std::borrow::Cow;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_did_str", borrow = "DIDStr", deserialize, serialize)]
pub struct DID(String);

impl DID {
    /// Construct a DID with the given host, port, path, and self-hash.
    pub fn new(
        host: &str,
        port_o: Option<u16>,
        path_o: Option<&str>,
        root_self_hash: &selfhash::KERIHashStr,
    ) -> Result<Self, Error> {
        let s = DIDWebplusURIComponents {
            host,
            port_o,
            path_o,
            root_self_hash,
            query_self_hash_o: None,
            query_version_id_o: None,
            relative_resource_o: None,
            fragment_o: None,
        }
        .to_string();
        Self::try_from(s)
    }
    /// Parse (the equivalent of) a resolution URL to produce a DID.
    pub fn from_resolution_url(host: &str, port_o: Option<u16>, path: &str) -> Result<Self, Error> {
        if path.starts_with('/') {
            return Err(Error::Malformed(
                "resolution URL path must not start with '/'",
            ));
        }
        if !path.ends_with("/did.json") {
            return Err(Error::Malformed(
                "resolution URL path must end with 'did.json'",
            ));
        }
        let path_and_root_self_hash_str = path.strip_suffix("/did.json").unwrap();
        let (path_o, root_self_hash_str) = match path_and_root_self_hash_str.rsplit_once('/') {
            Some((path, root_self_hash_str)) => {
                // Replace all the '/' chars with ':' chars.
                let path = path.replace('/', ":");
                // Self::new_with_self_hash_str(host, Some(path.as_str()), self_hash_str)
                (Some(path), root_self_hash_str)
            }
            None => {
                let root_self_hash_str = path_and_root_self_hash_str;
                // return Self::new_with_self_hash_str(host, None, self_hash_str);
                (None, root_self_hash_str)
            }
        };
        let root_self_hash = selfhash::KERIHashStr::new_ref(root_self_hash_str)?;
        Self::new(host, port_o, path_o.as_deref(), root_self_hash)
    }
    /// Parse (the equivalent of) a did-documents.jsonl resolution URL to produce a DID.
    // TEMP HACK
    pub fn from_did_documents_jsonl_resolution_url(
        host: &str,
        port_o: Option<u16>,
        path: &str,
    ) -> Result<Self, Error> {
        if path.starts_with('/') {
            return Err(Error::Malformed(
                "resolution URL path must not start with '/'",
            ));
        }
        if !path.ends_with("/did-documents.jsonl") {
            return Err(Error::Malformed(
                "did-documents.jsonl resolution URL path must end with 'did-documents.jsonl'",
            ));
        }
        let path_and_root_self_hash_str = path.strip_suffix("/did-documents.jsonl").unwrap();
        let (path_o, root_self_hash_str) = match path_and_root_self_hash_str.rsplit_once('/') {
            Some((path, root_self_hash_str)) => {
                // Replace all the '/' chars with ':' chars.
                let path = path.replace('/', ":");
                // Self::new_with_self_hash_str(host, Some(path.as_str()), self_hash_str)
                (Some(path), root_self_hash_str)
            }
            None => {
                let root_self_hash_str = path_and_root_self_hash_str;
                // return Self::new_with_self_hash_str(host, None, self_hash_str);
                (None, root_self_hash_str)
            }
        };
        let root_self_hash = selfhash::KERIHashStr::new_ref(root_self_hash_str)?;
        Self::new(host, port_o, path_o.as_deref(), root_self_hash)
    }
    /// Set the root self hash value to the given value.
    pub fn set_root_self_hash(&mut self, root_self_hash: &selfhash::KERIHashStr) {
        // Strip off the root self_hash portion, not including the ':' delimiter before it.
        self.0.truncate(self.0.rfind(':').unwrap() + 1);
        self.0.push_str(root_self_hash.as_str());
        use pneutype::Validate;
        debug_assert!(
            DIDStr::validate(self.0.as_str()).is_ok(),
            "programmer error"
        );
    }
}

/// This implementation is to allow a `&DID` to function as a `&dyn selfhash::Hash`, which is necessary
/// for the self-hashing functionality.  A DID isn't strictly "a Hash", more like it "has a Hash", but
/// this semantic difference isn't worth doing anything about.
impl selfhash::Hash for DID {
    fn hash_function(&self) -> selfhash::Result<&'static dyn selfhash::HashFunction> {
        self.root_self_hash().hash_function()
    }
    fn as_preferred_hash_format<'s: 'h, 'h>(
        &'s self,
    ) -> selfhash::Result<selfhash::PreferredHashFormat<'h>> {
        Ok(Cow::Borrowed(self.root_self_hash()).into())
    }
}
