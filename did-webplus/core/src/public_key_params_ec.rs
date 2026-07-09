use crate::Error;

// "kty" of "EC" is used for curves including "secp256k1", "P-256" (which is sometimes also called "secp256r1"),
// "P-384", and "P-521".
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyParamsEC {
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl PublicKeyParamsEC {
    /// Convenience function for creating the PublicKeyParamsEC for a secp256k1 key.
    pub fn secp256k1(x: String, y: String) -> Self {
        Self {
            crv: "secp256k1".into(),
            x,
            y,
        }
    }
    /// Convenience function for creating the PublicKeyParamsEC for a P-256 key (which is
    /// called secp256r1 in some other contexts).
    pub fn p256(x: String, y: String) -> Self {
        Self {
            crv: "P-256".into(),
            x,
            y,
        }
    }
    /// Convenience function for creating the PublicKeyParamsEC for a P-384 key.
    pub fn p384(x: String, y: String) -> Self {
        Self {
            crv: "P-384".into(),
            x,
            y,
        }
    }
    /// Convenience function for creating the PublicKeyParamsEC for a P-521 key.
    pub fn p521(x: String, y: String) -> Self {
        Self {
            crv: "P-521".into(),
            x,
            y,
        }
    }
}

impl TryFrom<&PublicKeyParamsEC> for mbx::MBPubKey {
    type Error = Error;
    fn try_from(public_key_params_ec: &PublicKeyParamsEC) -> Result<Self, Self::Error> {
        match public_key_params_ec.crv.as_str() {
            "secp256k1" => {
                #[cfg(feature = "k256")]
                {
                    // Base64-decode the x and y coordinates.
                    use k256::elliptic_curve::point::AffineCoordinates;
                    let mut x_buffer = [0u8; 33];
                    let mut y_buffer = [0u8; 33];
                    let x = crate::base64_decode_256_bits(
                        public_key_params_ec.x.as_str(),
                        &mut x_buffer,
                    )
                    .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    let y = crate::base64_decode_256_bits(
                        public_key_params_ec.y.as_str(),
                        &mut y_buffer,
                    )
                    .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    let affine_point_cto = k256::AffinePoint::from_coordinates(x.into(), y.into());
                    if affine_point_cto.is_none().unwrap_u8() != 0 {
                        return Err(Error::Malformed("invalid secp256k1 coordinates".into()));
                    }
                    let affine_point = affine_point_cto.unwrap();
                    let verifying_key = k256::ecdsa::VerifyingKey::from_affine(affine_point)
                        .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    // Encode the verifying key as a MBPubKey.
                    Ok(mbx::MBPubKey::from_k256_verifying_key(
                        mbx::Base::Base64Url,
                        &verifying_key,
                    ))
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!(
                        "secp256k1 keys require the k256 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            "P-256" => {
                #[cfg(feature = "p256")]
                {
                    // Base64-decode the x and y coordinates.
                    use p256::elliptic_curve::point::AffineCoordinates;
                    let mut x_buffer = [0u8; 33];
                    let mut y_buffer = [0u8; 33];
                    let x = crate::base64_decode_256_bits(
                        public_key_params_ec.x.as_str(),
                        &mut x_buffer,
                    )
                    .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    let y = crate::base64_decode_256_bits(
                        public_key_params_ec.y.as_str(),
                        &mut y_buffer,
                    )
                    .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    let affine_point_cto = p256::AffinePoint::from_coordinates(x.into(), y.into());
                    if affine_point_cto.is_none().unwrap_u8() != 0 {
                        return Err(Error::Malformed("invalid P-256 coordinates".into()));
                    }
                    let affine_point = affine_point_cto.unwrap();
                    let verifying_key = p256::ecdsa::VerifyingKey::from_affine(affine_point)
                        .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    // Encode the verifying key as a MBPubKey.
                    Ok(mbx::MBPubKey::from_p256_verifying_key(
                        mbx::Base::Base64Url,
                        &verifying_key,
                    ))
                }
                #[cfg(not(feature = "p256"))]
                {
                    panic!(
                        "P-256 keys require the p256 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            "P-384" => {
                #[cfg(feature = "p384")]
                {
                    // Base64-decode the x and y coordinates.
                    use p384::elliptic_curve::point::AffineCoordinates;
                    let mut x_buffer = [0u8; 48];
                    let mut y_buffer = [0u8; 48];
                    let x = crate::base64_decode_384_bits(
                        public_key_params_ec.x.as_str(),
                        &mut x_buffer,
                    )
                    .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    let y = crate::base64_decode_384_bits(
                        public_key_params_ec.y.as_str(),
                        &mut y_buffer,
                    )
                    .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    let affine_point_cto = p384::AffinePoint::from_coordinates(x.into(), y.into());
                    if affine_point_cto.is_none().unwrap_u8() != 0 {
                        return Err(Error::Malformed("invalid P-384 coordinates".into()));
                    }
                    let affine_point = affine_point_cto.unwrap();
                    let verifying_key = p384::ecdsa::VerifyingKey::from_affine(affine_point)
                        .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    // Encode the verifying key as a MBPubKey.
                    Ok(mbx::MBPubKey::from_p384_verifying_key(
                        mbx::Base::Base64Url,
                        &verifying_key,
                    ))
                }
                #[cfg(not(feature = "p384"))]
                {
                    panic!(
                        "P-384 keys require the p384 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            "P-521" => {
                #[cfg(feature = "p521")]
                {
                    // Base64-decode the x and y coordinates.
                    use p521::elliptic_curve::point::AffineCoordinates;
                    let mut x_buffer = [0u8; 66];
                    let mut y_buffer = [0u8; 66];
                    let x = crate::base64_decode_521_bits(
                        public_key_params_ec.x.as_str(),
                        &mut x_buffer,
                    )
                    .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    let y = crate::base64_decode_521_bits(
                        public_key_params_ec.y.as_str(),
                        &mut y_buffer,
                    )
                    .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    let affine_point_cto = p521::AffinePoint::from_coordinates(x.into(), y.into());
                    if affine_point_cto.is_none().unwrap_u8() != 0 {
                        return Err(Error::Malformed("invalid P-521 coordinates".into()));
                    }
                    let affine_point = affine_point_cto.unwrap();
                    let verifying_key = p521::ecdsa::VerifyingKey::from_affine(affine_point)
                        .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    // Encode the verifying key as a MBPubKey.
                    Ok(mbx::MBPubKey::from_p521_verifying_key(
                        mbx::Base::Base64Url,
                        &verifying_key,
                    ))
                }
                #[cfg(not(feature = "p521"))]
                {
                    panic!(
                        "P-521 keys require the p521 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            _ => Err(Error::Unrecognized(
                format!("EC curve: {}", public_key_params_ec.crv).into(),
            )),
        }
    }
}

impl TryFrom<&dyn signature_dyn::VerifierT> for PublicKeyParamsEC {
    type Error = Error;
    fn try_from(verifier: &dyn signature_dyn::VerifierT) -> Result<Self, Self::Error> {
        match verifier.key_type() {
            signature_dyn::KeyType::Secp256k1 => {
                #[cfg(feature = "k256")]
                {
                    let verifier_bytes = verifier.get_raw_bytes();
                    let verifying_key =
                        k256::ecdsa::VerifyingKey::from_sec1_bytes(verifier_bytes.as_ref())
                            .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    (&verifying_key).try_into()
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!(
                        "secp256k1 keys require the k256 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            signature_dyn::KeyType::P256 => {
                #[cfg(feature = "p256")]
                {
                    let verifier_bytes = verifier.get_raw_bytes();
                    let verifying_key =
                        p256::ecdsa::VerifyingKey::from_sec1_bytes(verifier_bytes.as_ref())
                            .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    (&verifying_key).try_into()
                }
                #[cfg(not(feature = "p256"))]
                {
                    panic!(
                        "P-256 keys require the p256 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            signature_dyn::KeyType::P384 => {
                #[cfg(feature = "p384")]
                {
                    let verifier_bytes = verifier.get_raw_bytes();
                    let verifying_key =
                        p384::ecdsa::VerifyingKey::from_sec1_bytes(verifier_bytes.as_ref())
                            .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    (&verifying_key).try_into()
                }
                #[cfg(not(feature = "p384"))]
                {
                    panic!(
                        "P-384 keys require the p384 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            signature_dyn::KeyType::P521 => {
                #[cfg(feature = "p521")]
                {
                    let verifier_bytes = verifier.get_raw_bytes();
                    let verifying_key =
                        p521::ecdsa::VerifyingKey::from_sec1_bytes(verifier_bytes.as_ref())
                            .map_err(|e| Error::Malformed(e.to_string().into()))?;
                    (&verifying_key).try_into()
                }
                #[cfg(not(feature = "p521"))]
                {
                    panic!(
                        "P-521 keys require the p521 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            signature_dyn::KeyType::Ed25519 | signature_dyn::KeyType::Ed448 => {
                Err(Error::Malformed(
                    "Ed25519 and Ed448 keys should use PublicKeyParamsOKP, not PublicKeyParamsEC"
                        .into(),
                ))
            }
            _ => Err(Error::Unrecognized(
                format!("EC curve: {}", verifier.key_type()).into(),
            )),
        }
    }
}

impl TryFrom<&mbx::MBPubKeyStr> for PublicKeyParamsEC {
    type Error = Error;
    fn try_from(pub_key: &mbx::MBPubKeyStr) -> Result<Self, Self::Error> {
        let decoded = pub_key.decoded().unwrap();
        match decoded.codec() {
            ssi_multicodec::SECP256K1_PUB => {
                #[cfg(feature = "k256")]
                {
                    let verifying_key = k256::ecdsa::VerifyingKey::try_from(pub_key)?;
                    (&verifying_key).try_into()
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!(
                        "secp256k1 keys require the k256 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            ssi_multicodec::P256_PUB => {
                #[cfg(feature = "p256")]
                {
                    let verifying_key = p256::ecdsa::VerifyingKey::try_from(pub_key)?;
                    (&verifying_key).try_into()
                }
                #[cfg(not(feature = "p256"))]
                {
                    panic!(
                        "P-256 keys require the p256 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            ssi_multicodec::P384_PUB => {
                #[cfg(feature = "p384")]
                {
                    let verifying_key = p384::ecdsa::VerifyingKey::try_from(pub_key)?;
                    (&verifying_key).try_into()
                }
                #[cfg(not(feature = "p384"))]
                {
                    panic!(
                        "P-384 keys require the p384 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            ssi_multicodec::P521_PUB => {
                #[cfg(feature = "p521")]
                {
                    let verifying_key = p521::ecdsa::VerifyingKey::try_from(pub_key)?;
                    (&verifying_key).try_into()
                }
                #[cfg(not(feature = "p521"))]
                {
                    panic!(
                        "P-521 keys require the p521 feature to be enabled on did-webplus-core crate"
                    );
                }
            }
            ssi_multicodec::ED25519_PUB | ssi_multicodec::ED448_PUB => Err(Error::Malformed(
                "Ed25519 and Ed448 keys should use PublicKeyParamsOKP, not PublicKeyParamsEC"
                    .into(),
            )),
            _ => Err(Error::Unrecognized(
                format!("EC curve: {}", decoded.codec()).into(),
            )),
        }
    }
}

#[cfg(feature = "k256")]
impl TryFrom<&k256::ecdsa::VerifyingKey> for PublicKeyParamsEC {
    type Error = Error;
    fn try_from(verifying_key: &k256::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
        // Field element is 32 bytes, so we need 43 base64 chars to encode each coordinate (x and y).
        use k256::elliptic_curve::point::AffineCoordinates;
        let mut buffer = [0u8; 43];
        let x = crate::base64_encode_256_bits(&verifying_key.as_affine().x().as_ref(), &mut buffer)
            .to_string();
        let y = crate::base64_encode_256_bits(&verifying_key.as_affine().y().as_ref(), &mut buffer)
            .to_string();
        Ok(Self {
            crv: "secp256k1".into(),
            x,
            y,
        })
    }
}

#[cfg(feature = "p256")]
impl TryFrom<&p256::ecdsa::VerifyingKey> for PublicKeyParamsEC {
    type Error = Error;
    fn try_from(verifying_key: &p256::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
        // Field element is 32 bytes, so we need 43 base64 chars to encode each coordinate (x and y).
        use p256::elliptic_curve::point::AffineCoordinates;
        let mut buffer = [0u8; 43];
        let x = crate::base64_encode_256_bits(&verifying_key.as_affine().x().as_ref(), &mut buffer)
            .to_string();
        let y = crate::base64_encode_256_bits(&verifying_key.as_affine().y().as_ref(), &mut buffer)
            .to_string();
        Ok(Self {
            crv: "P-256".into(),
            x,
            y,
        })
    }
}

#[cfg(feature = "p384")]
impl TryFrom<&p384::ecdsa::VerifyingKey> for PublicKeyParamsEC {
    type Error = Error;
    fn try_from(verifying_key: &p384::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
        // Field element is 48 bytes, so we need 64 base64 chars to encode each coordinate (x and y).
        use p384::elliptic_curve::point::AffineCoordinates;
        let mut buffer = [0u8; 64];
        let x = crate::base64_encode_384_bits(&verifying_key.as_affine().x().as_ref(), &mut buffer)
            .to_string();
        let y = crate::base64_encode_384_bits(&verifying_key.as_affine().y().as_ref(), &mut buffer)
            .to_string();
        Ok(Self {
            crv: "P-384".into(),
            x,
            y,
        })
    }
}

#[cfg(feature = "p521")]
impl TryFrom<&p521::ecdsa::VerifyingKey> for PublicKeyParamsEC {
    type Error = Error;
    fn try_from(verifying_key: &p521::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
        // Field element is 66 bytes, so we need 88 base64 chars to encode each coordinate (x and y).
        use p521::elliptic_curve::point::AffineCoordinates;
        let mut buffer = [0u8; 88];
        let x = crate::base64_encode_521_bits(&verifying_key.as_affine().x().as_ref(), &mut buffer)
            .to_string();
        let y = crate::base64_encode_521_bits(&verifying_key.as_affine().y().as_ref(), &mut buffer)
            .to_string();
        Ok(Self {
            crv: "P-521".into(),
            x,
            y,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "k256")]
    #[test]
    fn test_roundtrip_public_key_params_ec_secp256k1() {
        use signature_dyn::GenerateRandom;
        let signing_key = k256::ecdsa::SigningKey::generate_random();
        let verifying_key = signing_key.verifying_key();
        let public_key_params_ec = PublicKeyParamsEC::try_from(verifying_key).unwrap();
        let mb_pub_key = mbx::MBPubKey::try_from(&public_key_params_ec).unwrap();
        let recovered_verifying_key = k256::ecdsa::VerifyingKey::try_from(&mb_pub_key).unwrap();
        assert_eq!(verifying_key, &recovered_verifying_key);
    }

    #[cfg(feature = "p256")]
    #[test]
    fn test_roundtrip_public_key_params_ec_p256() {
        use signature_dyn::GenerateRandom;
        let signing_key = p256::ecdsa::SigningKey::generate_random();
        let verifying_key = signing_key.verifying_key();
        let public_key_params_ec = PublicKeyParamsEC::try_from(verifying_key).unwrap();
        let mb_pub_key = mbx::MBPubKey::try_from(&public_key_params_ec).unwrap();
        let recovered_verifying_key = p256::ecdsa::VerifyingKey::try_from(&mb_pub_key).unwrap();
        assert_eq!(verifying_key, &recovered_verifying_key);
    }

    #[cfg(feature = "p384")]
    #[test]
    fn test_roundtrip_public_key_params_ec_p384() {
        use signature_dyn::GenerateRandom;
        let signing_key = p384::ecdsa::SigningKey::generate_random();
        let verifying_key = signing_key.verifying_key();
        let public_key_params_ec = PublicKeyParamsEC::try_from(verifying_key).unwrap();
        let mb_pub_key = mbx::MBPubKey::try_from(&public_key_params_ec).unwrap();
        let recovered_verifying_key = p384::ecdsa::VerifyingKey::try_from(&mb_pub_key).unwrap();
        assert_eq!(verifying_key, &recovered_verifying_key);
    }

    #[cfg(feature = "p521")]
    #[test]
    fn test_roundtrip_public_key_params_ec_p521() {
        use signature_dyn::GenerateRandom;
        let signing_key = p521::ecdsa::SigningKey::generate_random();
        let verifying_key = signing_key.verifying_key();
        let public_key_params_ec = PublicKeyParamsEC::try_from(verifying_key).unwrap();
        let mb_pub_key = mbx::MBPubKey::try_from(&public_key_params_ec).unwrap();
        let recovered_verifying_key = p521::ecdsa::VerifyingKey::try_from(&mb_pub_key).unwrap();
        assert_eq!(verifying_key, &recovered_verifying_key);
    }
}
