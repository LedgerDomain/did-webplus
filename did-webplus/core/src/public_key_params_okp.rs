use crate::{Error, base64_encode_256_bits, base64_encode_456_bits};

// "kty" of "OKP" is used for curves including "Ed25519".
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyParamsOKP {
    pub crv: String,
    pub x: String,
}

impl PublicKeyParamsOKP {
    /// Convenience function for creating the PublicKeyParamsOKP for an Ed25519 key.
    pub fn ed25519(x: String) -> Self {
        Self {
            crv: "Ed25519".into(),
            x,
        }
    }
    /// Convenience function for creating the PublicKeyParamsOKP for an Ed448 key.
    pub fn ed448(x: String) -> Self {
        Self {
            crv: "Ed448".into(),
            x,
        }
    }
}

impl TryFrom<&mbx::MBPubKeyStr> for PublicKeyParamsOKP {
    type Error = Error;
    fn try_from(pub_key: &mbx::MBPubKeyStr) -> Result<Self, Self::Error> {
        let decoded = pub_key.decoded().unwrap();
        match decoded.codec() {
            ssi_multicodec::ED25519_PUB => {
                let mut buffer = [0u8; 43];
                let public_key_base64 = base64_encode_256_bits(
                    <&[u8; 32]>::try_from(decoded.data())
                        .map_err(|_| Error::Malformed("Invalid Ed25519 public key".into()))?,
                    &mut buffer,
                );
                Ok(Self {
                    crv: "Ed25519".into(),
                    x: public_key_base64.to_string(),
                })
            }
            ssi_multicodec::ED448_PUB => {
                let mut buffer = [0u8; 76];
                let public_key_base64 = base64_encode_456_bits(
                    <&[u8; 57]>::try_from(decoded.data())
                        .map_err(|_| Error::Malformed("Invalid Ed448 public key".into()))?,
                    &mut buffer,
                );
                Ok(Self {
                    crv: "Ed448".into(),
                    x: public_key_base64.to_string(),
                })
            }
            ssi_multicodec::SECP256K1_PUB | ssi_multicodec::P256_PUB | ssi_multicodec::P384_PUB | ssi_multicodec::P521_PUB => {
                Err(Error::Malformed("Secp256k1, P256, P384, and P521 keys should use PublicKeyParamsEC, not PublicKeyParamsOKP".into()))
            }
            _ => {
                return Err(Error::Unrecognized(
                    format!(
                        "public key type not supported for PublicKeyParamsOKP: {}",
                        decoded.codec()
                    )
                    .into(),
                ));
            }
        }
    }
}

impl TryFrom<&PublicKeyParamsOKP> for mbx::MBPubKey {
    type Error = Error;
    fn try_from(public_key_params_okp: &PublicKeyParamsOKP) -> Result<Self, Self::Error> {
        match public_key_params_okp.crv.as_str() {
            "Ed25519" => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let mut buffer = [0u8; 33];
                    let public_key_bytes = crate::base64_decode_256_bits(
                        public_key_params_okp.x.as_str(),
                        &mut buffer,
                    )
                    .map_err(|_| {
                        Error::Malformed("Invalid Base64URL encoding of Ed25519 public key".into())
                    })?;
                    let verifying_key =
                        ed25519_dalek::VerifyingKey::try_from(&public_key_bytes[..])
                            .map_err(|_| Error::Malformed("Invalid Ed25519 public key".into()))?;
                    Ok(mbx::MBPubKey::from_ed25519_dalek_verifying_key(
                        mbx::Base::Base64Url,
                        &verifying_key,
                    ))
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!(
                        "Must enable the `ed25519-dalek` feature to parse Ed25519 keys from PublicKeyParamsOKP"
                    );
                }
            }
            "Ed448" => {
                #[cfg(feature = "ed448-goldilocks")]
                {
                    let mut buffer = [0u8; 57];
                    let public_key_bytes = crate::base64_decode_456_bits(
                        public_key_params_okp.x.as_str(),
                        &mut buffer,
                    )
                    .map_err(|_| {
                        Error::Malformed("Invalid Base64URL encoding of Ed448 public key".into())
                    })?;
                    let verifying_key =
                        ed448_goldilocks::VerifyingKey::from_bytes(public_key_bytes)
                            .map_err(|_| Error::Malformed("Invalid Ed448 public key".into()))?;
                    Ok(mbx::MBPubKey::from_ed448_goldilocks_verifying_key(
                        mbx::Base::Base64Url,
                        &verifying_key,
                    ))
                }
                #[cfg(not(feature = "ed448-goldilocks"))]
                {
                    panic!(
                        "Must enable the `ed448-goldilocks` feature to parse Ed448 keys from PublicKeyParamsOKP"
                    );
                }
            }
            _ => Err(Error::Unrecognized(
                format!("OKP curve: {}", public_key_params_okp.crv).into(),
            )),
        }
    }
}

impl TryFrom<&ed25519_dalek::VerifyingKey> for PublicKeyParamsOKP {
    type Error = Error;
    fn try_from(verifying_key: &ed25519_dalek::VerifyingKey) -> Result<Self, Self::Error> {
        let mut buffer = [0u8; 43];
        let public_key_base64 =
            crate::base64_encode_256_bits(verifying_key.as_bytes(), &mut buffer);
        Ok(Self {
            crv: "Ed25519".into(),
            x: public_key_base64.to_string(),
        })
    }
}

impl TryFrom<&ed448_goldilocks::VerifyingKey> for PublicKeyParamsOKP {
    type Error = Error;
    fn try_from(verifying_key: &ed448_goldilocks::VerifyingKey) -> Result<Self, Self::Error> {
        let mut buffer = [0u8; 76];
        let public_key_base64 =
            crate::base64_encode_456_bits(verifying_key.as_bytes(), &mut buffer);
        Ok(Self {
            crv: "Ed448".into(),
            x: public_key_base64.to_string(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "ed25519-dalek")]
    #[test]
    fn test_roundtrip_public_key_params_okp_ed25519() {
        use signature_dyn::GenerateRandom;
        let signing_key = ed25519_dalek::SigningKey::generate_random();
        let verifying_key = signing_key.verifying_key();
        let public_key_params_okp = PublicKeyParamsOKP::try_from(&verifying_key).unwrap();
        let mb_pub_key = mbx::MBPubKey::try_from(&public_key_params_okp).unwrap();
        let recovered_verifying_key = ed25519_dalek::VerifyingKey::try_from(&mb_pub_key).unwrap();
        assert_eq!(verifying_key, recovered_verifying_key);
    }

    #[cfg(feature = "ed448-goldilocks")]
    #[test]
    fn test_roundtrip_public_key_params_okp_ed448() {
        use signature_dyn::GenerateRandom;
        let signing_key = ed448_goldilocks::SigningKey::generate_random();
        let verifying_key = signing_key.verifying_key();
        let public_key_params_okp = PublicKeyParamsOKP::try_from(&verifying_key).unwrap();
        let mb_pub_key = mbx::MBPubKey::try_from(&public_key_params_okp).unwrap();
        let recovered_verifying_key =
            ed448_goldilocks::VerifyingKey::try_from(&mb_pub_key).unwrap();
        assert_eq!(verifying_key, recovered_verifying_key);
    }
}
