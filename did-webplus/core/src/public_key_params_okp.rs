use crate::Error;

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

impl TryFrom<&mbc::MBPubKeyStr> for PublicKeyParamsOKP {
    type Error = Error;
    fn try_from(pub_key: &mbc::MBPubKeyStr) -> Result<Self, Self::Error> {
        let decoded = pub_key.decoded().unwrap();
        match decoded.codec() {
            ssi_multicodec::ED25519_PUB => {
                let mut buffer = [0u8; 43];
                let public_key_base64 = selfhash::base64_encode_256_bits(
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

impl TryFrom<&PublicKeyParamsOKP> for mbc::MBPubKey {
    type Error = Error;
    fn try_from(public_key_params_okp: &PublicKeyParamsOKP) -> Result<Self, Self::Error> {
        match public_key_params_okp.crv.as_str() {
            "Ed25519" => {
                let mut buffer = [0u8; 33];
                let public_key_bytes =
                    selfhash::base64_decode_256_bits(public_key_params_okp.x.as_str(), &mut buffer)
                        .map_err(|_| {
                            Error::Malformed("Invalid Base64URL encoding of Ed25519 public key")
                        })?;
                let verifying_key = ed25519_dalek::VerifyingKey::try_from(&public_key_bytes[..])
                    .map_err(|_| Error::Malformed("Invalid Ed25519 public key"))?;
                Ok(mbc::MBPubKey::from_ed25519_dalek_verifying_key(
                    mbc::Base::Base64Url,
                    &verifying_key,
                ))
            }
            _ => Err(Error::Unrecognized("OKP curve")),
        }
    }
}
