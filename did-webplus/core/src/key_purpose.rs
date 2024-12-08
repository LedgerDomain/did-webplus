use crate::{Error, KeyPurposeFlags};

/// Enumeration of the purposes of verification methods, as specified by the DID spec.
#[repr(u8)]
#[derive(Clone, Copy, Debug, enum_map::Enum, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub enum KeyPurpose {
    Authentication = 0,
    AssertionMethod = 1,
    KeyAgreement = 2,
    CapabilityInvocation = 3,
    CapabilityDelegation = 4,
}

impl KeyPurpose {
    /// An ordered array of all the variants in KeyPurpose.
    pub const VARIANTS: [KeyPurpose; 5] = [
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
            _ => Err(Error::Unrecognized("KeyPurpose integer value")),
        }
    }
}
