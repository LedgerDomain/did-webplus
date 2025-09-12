use crate::{Error, KeyPurposeFlags};

/// Enumeration of the purposes of verification methods, as specified by the DID spec.
#[repr(u8)]
#[derive(Clone, Copy, Debug, enum_map::Enum, Eq, Hash, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum KeyPurpose {
    Authentication = 0,
    AssertionMethod = 1,
    KeyAgreement = 2,
    CapabilityInvocation = 3,
    CapabilityDelegation = 4,
    UpdateDIDDocument = 5,
}

impl KeyPurpose {
    /// An ordered array of all the variants in KeyPurpose.  In particular, this includes UpdateDIDDocument,
    /// which is not a verification method in the sense of the DID spec, but is a did:webplus-specific purpose.
    pub const VARIANTS: [KeyPurpose; 6] = [
        KeyPurpose::Authentication,
        KeyPurpose::AssertionMethod,
        KeyPurpose::KeyAgreement,
        KeyPurpose::CapabilityInvocation,
        KeyPurpose::CapabilityDelegation,
        KeyPurpose::UpdateDIDDocument,
    ];
    /// An ordered array of all the variants in KeyPurpose that pertain to verification methods for DID documents.
    pub const VERIFICATION_METHOD_VARIANTS: [KeyPurpose; 5] = [
        KeyPurpose::Authentication,
        KeyPurpose::AssertionMethod,
        KeyPurpose::KeyAgreement,
        KeyPurpose::CapabilityInvocation,
        KeyPurpose::CapabilityDelegation,
    ];
    /// Number of variants in KeyPurpose.
    pub const fn variant_count() -> u8 {
        Self::VARIANTS.len() as u8
    }
    /// Number of verification method variants in KeyPurpose.
    pub const fn verification_method_variant_count() -> u8 {
        Self::VERIFICATION_METHOD_VARIANTS.len() as u8
    }
    pub const fn integer_value(self) -> u8 {
        self as u8
    }
    /// Produce the camelCase string for this variant, as used in the DID doc.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyPurpose::Authentication => "authentication",
            KeyPurpose::AssertionMethod => "assertionMethod",
            KeyPurpose::KeyAgreement => "keyAgreement",
            KeyPurpose::CapabilityInvocation => "capabilityInvocation",
            KeyPurpose::CapabilityDelegation => "capabilityDelegation",
            KeyPurpose::UpdateDIDDocument => "updateDIDDocument",
        }
    }
    /// Equivalent to KeyPurposeFlags::from(self).
    pub fn as_key_purpose_flags(self) -> KeyPurposeFlags {
        KeyPurposeFlags::from(self)
    }
}

impl std::fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for KeyPurpose {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authentication" => Ok(KeyPurpose::Authentication),
            "assertionMethod" => Ok(KeyPurpose::AssertionMethod),
            "keyAgreement" => Ok(KeyPurpose::KeyAgreement),
            "capabilityInvocation" => Ok(KeyPurpose::CapabilityInvocation),
            "capabilityDelegation" => Ok(KeyPurpose::CapabilityDelegation),
            "updateDIDDocument" => Ok(KeyPurpose::UpdateDIDDocument),
            _ => Err("Unrecognized KeyPurpose"),
        }
    }
}

impl TryFrom<u8> for KeyPurpose {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyPurpose::Authentication),
            1 => Ok(KeyPurpose::AssertionMethod),
            2 => Ok(KeyPurpose::KeyAgreement),
            3 => Ok(KeyPurpose::CapabilityInvocation),
            4 => Ok(KeyPurpose::CapabilityDelegation),
            5 => Ok(KeyPurpose::UpdateDIDDocument),
            _ => Err(Error::Unrecognized("KeyPurpose integer value")),
        }
    }
}
