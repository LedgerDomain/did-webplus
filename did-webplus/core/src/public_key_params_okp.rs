use crate::{Error, Result};

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
}

impl TryFrom<&mbx::MBPubKeyStr> for PublicKeyParamsOKP {
    type Error = Error;
    fn try_from(pub_key: &mbx::MBPubKeyStr) -> std::result::Result<Self, Self::Error> {
        let decoded = pub_key.decoded().unwrap();
        match decoded.codec() {
            ssi_multicodec::ED25519_PUB => {
                let mut buffer = [0u8; 43];
                let public_key_base64 = base64_encode_256_bits(
                    <&[u8; 32]>::try_from(decoded.data())
                        .map_err(|_| Error::Malformed("Invalid Ed25519 public key"))?,
                    &mut buffer,
                );
                Ok(Self {
                    crv: "Ed25519".into(),
                    x: public_key_base64.to_string(),
                })
            }
            ssi_multicodec::SECP256K1_PUB => {
                unimplemented!("blah");
            }
            ssi_multicodec::P256_PUB => {
                unimplemented!("blah");
            }
            _ => {
                return Err(Error::Unrecognized(
                    "public key type not supported for PublicKeyParamsOKP",
                ))
            }
        }
    }
}

impl TryFrom<&PublicKeyParamsOKP> for mbx::MBPubKey {
    type Error = Error;
    fn try_from(
        public_key_params_okp: &PublicKeyParamsOKP,
    ) -> std::result::Result<Self, Self::Error> {
        match public_key_params_okp.crv.as_str() {
            "Ed25519" => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    let mut buffer = [0u8; 33];
                    let public_key_bytes =
                        base64_decode_256_bits(public_key_params_okp.x.as_str(), &mut buffer)
                            .map_err(|_| {
                                Error::Malformed("Invalid Base64URL encoding of Ed25519 public key")
                            })?;
                    let verifying_key =
                        ed25519_dalek::VerifyingKey::try_from(&public_key_bytes[..])
                            .map_err(|_| Error::Malformed("Invalid Ed25519 public key"))?;
                    Ok(mbx::MBPubKey::from_ed25519_dalek_verifying_key(
                        mbx::Base::Base64Url,
                        &verifying_key,
                    ))
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("Must enable the `ed25519-dalek` feature to parse Ed25519 keys from PublicKeyParamsOKP");
                }
            }
            "Ed448" => {
                #[cfg(feature = "ed448-goldilocks")]
                {
                    todo!();
                }
                #[cfg(not(feature = "ed448-goldilocks"))]
                {
                    panic!("Must enable the `ed448-goldilocks` feature to parse Ed448 keys from PublicKeyParamsOKP");
                }
            }
            _ => Err(Error::Unrecognized("OKP curve")),
        }
    }
}

/// This function is to assist in no-alloc base64 encoding of 256 bits.
fn base64_encode_256_bits<'a>(input_byte_v: &[u8; 32], buffer: &'a mut [u8; 43]) -> &'a str {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(input_byte_v, buffer)
        .unwrap();
    std::str::from_utf8(&*buffer).unwrap()
}

/// This function is to assist in no-alloc base64 decoding of 256 bits.
/// 256 bits is 43 base64 chars (rounded up), but 43 base64 chars is 258 bits,
/// so there has to be an extra byte in the buffer for base64 to decode into.
fn base64_decode_256_bits<'a>(input_str: &str, buffer: &'a mut [u8; 33]) -> Result<&'a [u8; 32]> {
    if !input_str.is_ascii() {
        return Err(Error::Malformed("not ASCII"));
    }
    if input_str.len() != 43 {
        return Err(Error::Malformed("expected 43 base64 chars"));
    }
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(input_str.as_bytes(), buffer)
        .map_err(|_| "base64 decode of 256 bit value failed")?;
    // Ensure that the last byte is zero, otherwise there were more than 256 bits in the base64 string.
    if buffer[32] != 0 {
        return Err(Error::Malformed("does not parse as 256 bit value"));
    }
    // Cut off the last byte, which we know is zero.
    let output_byte_v: &[u8; 32] = buffer[0..32].try_into().unwrap();
    Ok(output_byte_v)
}
