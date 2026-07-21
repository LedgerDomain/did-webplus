/// Supported key types for test-vector generation.
///
/// Wraps the subset of [`signature_dyn::KeyType`] variants enabled for did:webplus.
/// Designed to be usable as a clap `ValueEnum` (via the crate's `clap` feature).
#[derive(
    Clone, Copy, Debug, serde::Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize,
)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum KeyTypeChoice {
    Ed25519,
    Ed448,
    P256,
    P384,
    P521,
    Secp256k1,
}

impl KeyTypeChoice {
    /// All supported variants, in a stable order.
    pub const VARIANTS: [KeyTypeChoice; 6] = [
        KeyTypeChoice::Ed25519,
        KeyTypeChoice::Ed448,
        KeyTypeChoice::P256,
        KeyTypeChoice::P384,
        KeyTypeChoice::P521,
        KeyTypeChoice::Secp256k1,
    ];

    /// Canonical string form used in metadata (matches [`signature_dyn::KeyType::as_str`]).
    pub fn as_str(self) -> &'static str {
        signature_dyn::KeyType::from(self).as_str()
    }
}

impl From<KeyTypeChoice> for signature_dyn::KeyType {
    fn from(value: KeyTypeChoice) -> Self {
        match value {
            KeyTypeChoice::Ed25519 => signature_dyn::KeyType::Ed25519,
            KeyTypeChoice::Ed448 => signature_dyn::KeyType::Ed448,
            KeyTypeChoice::P256 => signature_dyn::KeyType::P256,
            KeyTypeChoice::P384 => signature_dyn::KeyType::P384,
            KeyTypeChoice::P521 => signature_dyn::KeyType::P521,
            KeyTypeChoice::Secp256k1 => signature_dyn::KeyType::Secp256k1,
        }
    }
}

impl TryFrom<signature_dyn::KeyType> for KeyTypeChoice {
    type Error = anyhow::Error;

    fn try_from(value: signature_dyn::KeyType) -> Result<Self, Self::Error> {
        match value {
            signature_dyn::KeyType::Ed25519 => Ok(KeyTypeChoice::Ed25519),
            signature_dyn::KeyType::Ed448 => Ok(KeyTypeChoice::Ed448),
            signature_dyn::KeyType::P256 => Ok(KeyTypeChoice::P256),
            signature_dyn::KeyType::P384 => Ok(KeyTypeChoice::P384),
            signature_dyn::KeyType::P521 => Ok(KeyTypeChoice::P521),
            signature_dyn::KeyType::Secp256k1 => Ok(KeyTypeChoice::Secp256k1),
            other => anyhow::bail!("unsupported key type for test vectors: {:?}", other),
        }
    }
}

impl std::fmt::Display for KeyTypeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for KeyTypeChoice {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key_type = signature_dyn::KeyType::from_str(s)
            .map_err(|e| anyhow::anyhow!("invalid key type {:?}: {}", s, e))?;
        Self::try_from(key_type)
    }
}
