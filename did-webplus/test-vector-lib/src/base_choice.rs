/// Supported multibase encodings for self-hashes and public keys in test vectors.
///
/// Restricted to the two bases used by did:webplus coverage: Base64Url (preferred)
/// and Base58Btc. Designed to be usable as a clap `ValueEnum` (via the crate's
/// `clap` feature).
#[derive(
    Clone, Copy, Debug, serde::Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize,
)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum BaseChoice {
    /// Bitcoin-style base58 (used e.g. by did:key).
    Base58Btc,
    /// URL-safe base64 without padding (preferred for did:webplus).
    Base64Url,
}

impl BaseChoice {
    /// All supported variants, in a stable order.
    pub const VARIANTS: [BaseChoice; 2] = [BaseChoice::Base58Btc, BaseChoice::Base64Url];

    /// Canonical string form used in metadata and CLI.
    pub fn as_str(self) -> &'static str {
        match self {
            BaseChoice::Base58Btc => "base58btc",
            BaseChoice::Base64Url => "base64url",
        }
    }
}

impl From<BaseChoice> for mbx::Base {
    fn from(value: BaseChoice) -> Self {
        match value {
            BaseChoice::Base58Btc => mbx::Base::Base58Btc,
            BaseChoice::Base64Url => mbx::Base::Base64Url,
        }
    }
}

impl TryFrom<mbx::Base> for BaseChoice {
    type Error = anyhow::Error;

    fn try_from(value: mbx::Base) -> Result<Self, Self::Error> {
        match value {
            mbx::Base::Base58Btc => Ok(BaseChoice::Base58Btc),
            mbx::Base::Base64Url => Ok(BaseChoice::Base64Url),
            other => anyhow::bail!("unsupported multibase for test vectors: {:?}", other),
        }
    }
}

impl std::fmt::Display for BaseChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for BaseChoice {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "base58btc" | "Base58Btc" => Ok(BaseChoice::Base58Btc),
            "base64url" | "Base64Url" => Ok(BaseChoice::Base64Url),
            other => anyhow::bail!(
                "invalid multibase {:?}; expected base58btc or base64url",
                other
            ),
        }
    }
}
