use crate::Error;

pub enum PrivKeyUsageType {
    /// Use this key as the self-signing key in a DID create operation.
    DIDCreate,
    /// Use this key as the self-signing key in a DID update operation.
    DIDUpdate,
    /// Use this key to sign a generic piece of data.
    Sign,
    /// Use this key to sign a generic JWS.
    SignJWS,
    /// Use this key to sign a generic JWT.
    SignJWT,
    /// Use this key to sign a verifiable credential.
    SignVC,
    /// Use this key to sign a verifiable presentation.
    SignVP,
    /// Use this key in a key exchange operation.
    KeyExchange,
    /// Use this key in a key exchange operation with a given versioned DID's key.
    KeyExchangeWithDID,
}

impl PrivKeyUsageType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DIDCreate => "DIDCreate",
            Self::DIDUpdate => "DIDUpdate",
            Self::Sign => "Sign",
            Self::SignJWS => "SignJWS",
            Self::SignJWT => "SignJWT",
            Self::SignVC => "SignVC",
            Self::SignVP => "SignVP",
            Self::KeyExchange => "KeyExchange",
            Self::KeyExchangeWithDID => "KeyExchangeWithDID",
        }
    }
}

impl std::fmt::Display for PrivKeyUsageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PrivKeyUsageType {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "DIDCreate" => Ok(Self::DIDCreate),
            "DIDUpdate" => Ok(Self::DIDUpdate),
            "Sign" => Ok(Self::Sign),
            "SignJWS" => Ok(Self::SignJWS),
            "SignJWT" => Ok(Self::SignJWT),
            "SignVC" => Ok(Self::SignVC),
            "SignVP" => Ok(Self::SignVP),
            "KeyExchange" => Ok(Self::KeyExchange),
            "KeyExchangeWithDID" => Ok(Self::KeyExchangeWithDID),
            _ => Err(Error::Malformed(
                format!("Unrecognized PrivKeyUsageType {:?}", s).into(),
            )),
        }
    }
}
