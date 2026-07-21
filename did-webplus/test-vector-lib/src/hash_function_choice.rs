/// Supported hash functions for test-vector self-hashes.
///
/// Wraps the [`selfhash::NamedHashFunction`] variants enabled via selfhash's
/// `all-hash-functions` feature. Designed to be usable as a clap `ValueEnum`
/// (via the crate's `clap` feature).
#[derive(
    Clone, Copy, Debug, serde::Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize,
)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum HashFunctionChoice {
    Blake3,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashFunctionChoice {
    /// All supported variants, in a stable order.
    pub const VARIANTS: [HashFunctionChoice; 9] = [
        HashFunctionChoice::Blake3,
        HashFunctionChoice::Sha224,
        HashFunctionChoice::Sha256,
        HashFunctionChoice::Sha384,
        HashFunctionChoice::Sha512,
        HashFunctionChoice::Sha3_224,
        HashFunctionChoice::Sha3_256,
        HashFunctionChoice::Sha3_384,
        HashFunctionChoice::Sha3_512,
    ];

    /// Canonical string form used in metadata (matches [`selfhash::NamedHashFunction`]).
    pub fn as_str(self) -> &'static str {
        *self.as_named_hash_function()
    }

    /// Convert to the corresponding [`selfhash::NamedHashFunction`].
    pub fn as_named_hash_function(self) -> selfhash::NamedHashFunction {
        match self {
            HashFunctionChoice::Blake3 => selfhash::NamedHashFunction::BLAKE3,
            HashFunctionChoice::Sha224 => selfhash::NamedHashFunction::SHA224,
            HashFunctionChoice::Sha256 => selfhash::NamedHashFunction::SHA256,
            HashFunctionChoice::Sha384 => selfhash::NamedHashFunction::SHA384,
            HashFunctionChoice::Sha512 => selfhash::NamedHashFunction::SHA512,
            HashFunctionChoice::Sha3_224 => selfhash::NamedHashFunction::SHA3_224,
            HashFunctionChoice::Sha3_256 => selfhash::NamedHashFunction::SHA3_256,
            HashFunctionChoice::Sha3_384 => selfhash::NamedHashFunction::SHA3_384,
            HashFunctionChoice::Sha3_512 => selfhash::NamedHashFunction::SHA3_512,
        }
    }

    /// Build an [`selfhash::MBHashFunction`] for the given multibase encoding.
    pub fn as_mb_hash_function(self, base: mbx::Base) -> selfhash::MBHashFunction {
        self.as_named_hash_function().as_mb_hash_function(base)
    }
}

impl From<HashFunctionChoice> for selfhash::NamedHashFunction {
    fn from(value: HashFunctionChoice) -> Self {
        value.as_named_hash_function()
    }
}

impl TryFrom<selfhash::NamedHashFunction> for HashFunctionChoice {
    type Error = anyhow::Error;

    fn try_from(value: selfhash::NamedHashFunction) -> Result<Self, Self::Error> {
        for &variant in &Self::VARIANTS {
            if variant.as_named_hash_function() == value {
                return Ok(variant);
            }
        }
        anyhow::bail!("unsupported hash function for test vectors: {}", value)
    }
}

impl std::fmt::Display for HashFunctionChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for HashFunctionChoice {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let named = selfhash::NamedHashFunction::from_str(s)
            .map_err(|e| anyhow::anyhow!("invalid hash function {:?}: {}", s, e))?;
        Self::try_from(named)
    }
}
