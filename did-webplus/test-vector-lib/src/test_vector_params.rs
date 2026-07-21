use crate::{BaseChoice, HashFunctionChoice, KeyTypeChoice};

/// Parameters that fully determine the DID hostname/path shape and crypto choices
/// for a generated test vector.
///
/// Every vector records the params it was generated with so harnesses can
/// reconstruct generation context from metadata alone.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct TestVectorParams {
    /// DID hostname (e.g. `example.com`, `localhost`).
    pub host: String,
    /// Optional DID port (percent-encoded as `%3A<port>` in the DID).
    #[serde(rename = "port")]
    pub port_o: Option<u16>,
    /// DID path components between host and root self-hash (joined with `:`).
    #[serde(rename = "path_components")]
    pub path_component_v: Vec<String>,
    /// Primary key type used when generating keys for this vector.
    pub key_type: KeyTypeChoice,
    /// Primary hash function used for self-hashes in this vector.
    pub hash_function: HashFunctionChoice,
    /// Multibase encoding used for self-hashes / public keys in this vector.
    pub base: BaseChoice,
}

impl TestVectorParams {
    /// Baseline params used by most conformance vectors: ed25519 + BLAKE3 + base64url.
    pub fn baseline(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port_o: None,
            path_component_v: Vec::new(),
            key_type: KeyTypeChoice::Ed25519,
            hash_function: HashFunctionChoice::Blake3,
            base: BaseChoice::Base64Url,
        }
    }

    /// Join path components with `:`, or `None` when there are no path components.
    pub fn path_o(&self) -> Option<String> {
        if self.path_component_v.is_empty() {
            None
        } else {
            Some(self.path_component_v.join(":"))
        }
    }

    /// The [`selfhash::MBHashFunction`] implied by [`Self::hash_function`] and [`Self::base`].
    pub fn mb_hash_function(&self) -> selfhash::MBHashFunction {
        self.hash_function
            .as_mb_hash_function(mbx::Base::from(self.base))
    }
}
