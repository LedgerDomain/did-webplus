use crate::{Error, KeyPurpose};

/// KeyPurposeFlags is a compact, integer representation of a set of KeyPurpose values as bitflags.
/// Use KeyPurposeFlags::from(key_purpose) to construct a KeyPurposeFlags that has a single bitflag.
/// KeyPurposeFlags::NONE and KeyPurposeFlags::ALL are associated constants that represent the empty
/// set and the "full" set.  All the expected bit operations are defined.
#[derive(Clone, Copy, serde::Deserialize, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct KeyPurposeFlags(u8);

impl KeyPurposeFlags {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self((1u8 << KeyPurpose::variant_count()) - 1);
    pub fn integer_value(self) -> u8 {
        self.0
    }
    /// Returns true iff the given key_purpose is present in this KeyPurposeFlags value (considered as a set).
    pub fn contains(self, key_purpose: KeyPurpose) -> bool {
        (self & Self::from(key_purpose)) != Self::NONE
    }
    /// Returns true iff the given key_purpose_flags has a nonzero intersection with this KeyPurposeFlags
    /// value (considered as a set).
    pub fn intersects(self, key_purpose_flags: Self) -> bool {
        (self & key_purpose_flags) != Self::NONE
    }
}

impl std::ops::BitAnd for KeyPurposeFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        KeyPurposeFlags(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for KeyPurposeFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::BitOr for KeyPurposeFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        KeyPurposeFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for KeyPurposeFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitXor for KeyPurposeFlags {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        KeyPurposeFlags(self.0 ^ rhs.0)
    }
}

impl std::ops::BitXorAssign for KeyPurposeFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl std::fmt::Debug for KeyPurposeFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyPurposeFlags({})", self)
    }
}

impl std::fmt::Display for KeyPurposeFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut has_written = false;
        for key_purpose in KeyPurpose::VARIANTS {
            if self.contains(key_purpose) {
                if has_written {
                    write!(f, ",")?;
                }
                write!(f, "{}", key_purpose)?;
                has_written = true;
            }
        }
        Ok(())
    }
}

impl From<KeyPurpose> for KeyPurposeFlags {
    fn from(key_purpose: KeyPurpose) -> Self {
        Self(1u8 << key_purpose as u8)
    }
}

impl std::ops::Not for KeyPurposeFlags {
    type Output = Self;
    fn not(self) -> Self::Output {
        self ^ KeyPurposeFlags::ALL
    }
}

impl TryFrom<u8> for KeyPurposeFlags {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > KeyPurposeFlags::ALL.integer_value() {
            Err(Error::Malformed(
                format!("KeyPurposeFlags (value out of valid range): {}", value).into(),
            ))
        } else {
            Ok(Self(value))
        }
    }
}
