use crate::{DIDStr, Error};

#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_did_str", borrow = "DIDStr", deserialize, serialize)]
pub struct DID(String);

impl DID {
    /// Construct a DID with the given host, path, and self-hash.
    pub fn new(
        host: &str,
        path_o: Option<&str>,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Self, Error> {
        let did_string = format!(
            "did:webplus:{}:{}{}{}",
            host,
            path_o.unwrap_or(""),
            if path_o.is_some() { ":" } else { "" },
            self_hash
        );
        use pneutype::Validate;
        debug_assert!(
            DIDStr::validate(did_string.as_str()).is_ok(),
            "programmer error"
        );
        Ok(Self(did_string))
    }
    /// Parse (the equivalent of) a resolution URL to produce a DID.
    pub fn from_resolution_url(host: &str, path: &str) -> Result<Self, Error> {
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
        let path_and_self_hash_str = path.strip_suffix("/did.json").unwrap();
        let (path_o, self_hash_str) = match path_and_self_hash_str.rsplit_once('/') {
            Some((path, self_hash_str)) => {
                // Replace all the '/' chars with ':' chars.
                let path = path.replace('/', ":");
                // Self::new_with_self_hash_str(host, Some(path.as_str()), self_hash_str)
                (Some(path), self_hash_str)
            }
            None => {
                let self_hash_str = path_and_self_hash_str;
                // return Self::new_with_self_hash_str(host, None, self_hash_str);
                (None, self_hash_str)
            }
        };
        let self_hash = selfhash::KERIHashStr::new_ref(self_hash_str)?;
        Self::new(host, path_o.as_deref(), self_hash)
    }
    // TODO: Consider renaming "self hash" to "root self hash" to make it clear that it's distinct from
    // "query self hash".
    pub fn set_self_hash(&mut self, self_hash: &selfhash::KERIHashStr) {
        // Strip off the self_hash portion, not including the ':' delimiter before it.
        self.0.truncate(self.0.rfind(':').unwrap() + 1);
        self.0.push_str(self_hash.as_str());
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
    fn hash_function(&self) -> &dyn selfhash::HashFunction {
        self.self_hash().hash_function()
    }
    fn to_hash_bytes<'s: 'h, 'h>(&'s self) -> selfhash::HashBytes<'h> {
        self.self_hash().to_hash_bytes()
    }
    fn to_keri_hash<'s: 'h, 'h>(&'s self) -> std::borrow::Cow<'h, selfhash::KERIHashStr> {
        std::borrow::Cow::Borrowed(self.self_hash())
    }
}
