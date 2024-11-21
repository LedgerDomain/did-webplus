use crate::{
    DIDResource, Error, Result, DID_KEY_BLS12381_G2_PREFIX, DID_KEY_ED25519_PREFIX,
    DID_KEY_P256_PREFIX, DID_KEY_RSA_PREFIX, DID_KEY_SECP256K1_PREFIX,
};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", pneu_str(deserialize, serialize))]
#[repr(transparent)]
pub struct DIDStr(str);

impl DIDStr {
    /// This returns the method-specific value, which for did:key is a multibase string that
    /// directly encodes the public key being represented.
    pub fn multibase(&self) -> &str {
        // This unwrap is guaranteed to succeed because of pneutype validation.
        self.0.split(':').nth(2).unwrap()
    }
    pub fn with_fragment(&self) -> DIDResource {
        DIDResource::try_from(format!("{}#{}", &self.0, self.multibase())).expect(
            "programmer error: this should not be possible due to validation in the constructor",
        )
    }
    // TODO: Maybe &DIDStr itself should implement selfsign::Verifier
    pub fn to_verifier(&self) -> Box<dyn selfsign::Verifier> {
        // TODO: More efficient impl

        use crate::DID_KEY_ED25519_PREFIX;

        if !self.0.starts_with("did:key:") {
            panic!(
                "programmer error: this should have been ensured by validation in the constructor"
            );
        }
        let method_specific_id = &self.0[8..];
        let (_base, byte_v) = multibase::decode(method_specific_id).expect(
            "programmer error: this should not be possible due to validation in the constructor",
        );
        if byte_v.len() < 2 {
            panic!(
                "programmer error: this should have been ensured by validation in the constructor"
            );
        }

        if byte_v[0] == DID_KEY_ED25519_PREFIX[0] && byte_v[1] == DID_KEY_ED25519_PREFIX[1] {
            #[cfg(feature = "ed25519-dalek")]
            {
                if byte_v.len() - 2 != 32 {
                    panic!("programmer error: this should not be possible due to validation in the constructor")
                }
                let verifier_bytes = selfsign::VerifierBytes {
                    key_type: selfsign::KeyType::Ed25519,
                    verifying_key_byte_v: std::borrow::Cow::Borrowed(&byte_v[2..]),
                };
                let ed25519_verifying_key = ed25519_dalek::VerifyingKey::try_from(&verifier_bytes).expect("programmer error: this should not be possible due to validation in the constructor");
                Box::new(ed25519_verifying_key)
            }
            #[cfg(not(feature = "ed25519-dalek"))]
            {
                panic!(
                    "ed25519 key type not supported (ed25519-dalek cargo feature must be enabled)"
                );
            }
        } else if byte_v[0] == DID_KEY_SECP256K1_PREFIX[0]
            && byte_v[1] == DID_KEY_SECP256K1_PREFIX[1]
        {
            #[cfg(feature = "k256")]
            {
                if byte_v.len() - 2 != 33 {
                    panic!("programmer error: this should not be possible due to validation in the constructor")
                }
                let verifier_bytes = selfsign::VerifierBytes {
                    key_type: selfsign::KeyType::Secp256k1,
                    verifying_key_byte_v: std::borrow::Cow::Borrowed(&byte_v[2..]),
                };
                let secp256k1_verifying_key = k256::ecdsa::VerifyingKey::try_from(&verifier_bytes).expect("programmer error: this should not be possible due to validation in the constructor");
                Box::new(secp256k1_verifying_key)
            }
            #[cfg(not(feature = "k256"))]
            {
                panic!("secp256k1 key type not supported (k256 cargo feature must be enabled)");
            }
        } else {
            panic!("not yet supported");
        }
    }
    #[cfg(feature = "ed25519-dalek")]
    pub fn to_ed25519(&self) -> Result<ed25519_dalek::VerifyingKey> {
        use crate::DID_KEY_ED25519_PREFIX;

        if !self.0.starts_with("did:key:") {
            panic!(
                "programmer error: this should have been ensured by validation in the constructor"
            );
        }
        let method_specific_id = &self.0[8..];
        let (_base, byte_v) = multibase::decode(method_specific_id).map_err(|e| {
            anyhow::anyhow!("malformed did:key value: multibase decode failed: {}", e)
        })?;
        if byte_v.len() < 2 {
            panic!(
                "programmer error: this should have been ensured by validation in the constructor"
            );
        }

        if byte_v[0] == DID_KEY_ED25519_PREFIX[0] && byte_v[1] == DID_KEY_ED25519_PREFIX[1] {
            anyhow::ensure!(
                byte_v.len() - 2 == 32,
                "malformed ed25519 did:key value: invalid length"
            );
            let verifier_bytes = selfsign::VerifierBytes {
                key_type: selfsign::KeyType::Ed25519,
                verifying_key_byte_v: std::borrow::Cow::Borrowed(&byte_v[2..]),
            };
            Ok(ed25519_dalek::VerifyingKey::try_from(&verifier_bytes)
                .map_err(|e| anyhow::anyhow!("malformed ed25519 did:key value: {}", e))?)
        } else {
            anyhow::bail!("this did:key is not ed25519");
        }
    }
    #[cfg(feature = "k256")]
    pub fn to_secp256k1(&self) -> Result<k256::ecdsa::VerifyingKey> {
        use crate::DID_KEY_SECP256K1_PREFIX;

        if !self.0.starts_with("did:key:") {
            panic!(
                "programmer error: this should have been ensured by validation in the constructor"
            );
        }
        let method_specific_id = &self.0[8..];
        let (_base, byte_v) = multibase::decode(method_specific_id).map_err(|e| {
            anyhow::anyhow!("malformed did:key value: multibase decode failed: {}", e)
        })?;
        if byte_v.len() < 2 {
            panic!(
                "programmer error: this should have been ensured by validation in the constructor"
            );
        }

        if byte_v[0] == DID_KEY_SECP256K1_PREFIX[0] && byte_v[1] == DID_KEY_SECP256K1_PREFIX[1] {
            anyhow::ensure!(
                byte_v.len() - 2 == 33,
                "malformed secp256k1 did:key value: invalid length"
            );
            let verifier_bytes = selfsign::VerifierBytes {
                key_type: selfsign::KeyType::Secp256k1,
                verifying_key_byte_v: std::borrow::Cow::Borrowed(&byte_v[2..]),
            };
            Ok(k256::ecdsa::VerifyingKey::try_from(&verifier_bytes)
                .map_err(|e| anyhow::anyhow!("malformed secp256k1 did:key value: {}", e))?)
        } else {
            anyhow::bail!("this did:key is not secp256k1");
        }
    }
}

impl pneutype::Validate for DIDStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        anyhow::ensure!(
            data.starts_with("did:key:"),
            "malformed did:key value: was expected to start with \"did:key:\""
        );
        let method_specific_id = &data[8..];
        let (base, byte_v) = multibase::decode(method_specific_id).map_err(|e| {
            anyhow::anyhow!("malformed did:key value: multibase decode failed: {}", e)
        })?;
        log::debug!("DIDKeyStr::validate; multibase decode used base {:?}", base);
        anyhow::ensure!(
            byte_v.len() >= 2,
            "malformed did:key value: too short to be valid"
        );

        if byte_v[0] == DID_KEY_ED25519_PREFIX[0] && byte_v[1] == DID_KEY_ED25519_PREFIX[1] {
            #[cfg(feature = "ed25519-dalek")]
            {
                anyhow::ensure!(
                    byte_v.len() - 2 == 32,
                    "malformed ed25519 did:key value: invalid length"
                );
                let mut byte_v = byte_v;
                byte_v.drain(0..2);
                let verifier_bytes = selfsign::VerifierBytes {
                    key_type: selfsign::KeyType::Ed25519,
                    verifying_key_byte_v: std::borrow::Cow::Owned(byte_v),
                };
                let _ed25519_verifying_key = ed25519_dalek::VerifyingKey::try_from(&verifier_bytes)
                    .map_err(|e| anyhow::anyhow!("malformed ed25519 did:key value: {}", e))?;
                Ok(())
            }
            #[cfg(not(feature = "ed25519-dalek"))]
            {
                panic!(
                    "ed25519 key type not supported (ed25519-dalek cargo feature must be enabled)"
                );
            }
        } else if byte_v[0] == DID_KEY_SECP256K1_PREFIX[0]
            && byte_v[1] == DID_KEY_SECP256K1_PREFIX[1]
        {
            #[cfg(feature = "k256")]
            {
                anyhow::ensure!(
                    byte_v.len() - 2 == 33,
                    "malformed secp256k1 did:key value: invalid length"
                );
                let mut byte_v = byte_v;
                byte_v.drain(0..2);
                let verifier_bytes = selfsign::VerifierBytes {
                    key_type: selfsign::KeyType::Secp256k1,
                    verifying_key_byte_v: std::borrow::Cow::Owned(byte_v),
                };
                let _secp256k1_verifying_key = k256::ecdsa::VerifyingKey::try_from(&verifier_bytes)
                    .map_err(|e| anyhow::anyhow!("malformed secp256k1 did:key value: {}", e))?;
                Ok(())
            }
            #[cfg(not(feature = "k256"))]
            {
                panic!("secp256k1 key type not supported (k256 cargo feature must be enabled)");
            }
        } else if byte_v[0] == DID_KEY_P256_PREFIX[0] && byte_v[1] == DID_KEY_P256_PREFIX[1] {
            unimplemented!("p256 key type not yet supported");
        } else if byte_v[0] == DID_KEY_RSA_PREFIX[0] && byte_v[1] == DID_KEY_RSA_PREFIX[1] {
            anyhow::bail!("RSA key type not supported");
        } else if byte_v[0] == DID_KEY_BLS12381_G2_PREFIX[0]
            && byte_v[1] == DID_KEY_BLS12381_G2_PREFIX[1]
        {
            unimplemented!("Bls12381G2 key type not yet supported");
        } else {
            anyhow::bail!("Unknown (and therefore unsupported) key type");
        }
    }
}
