use crate::{DIDResource, Error, Result};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", pneu_str(deserialize, serialize))]
#[repr(transparent)]
pub struct DIDStr(str);

impl DIDStr {
    /// This returns the method-specific value, which for did:key is a multibase string that
    /// directly encodes the public key being represented.
    pub fn multibase(&self) -> &str {
        // This unwrap is guaranteed to succeed because of pneutype validation.
        self.0.strip_prefix("did:key:").unwrap()
    }
    pub fn with_fragment(&self) -> DIDResource {
        DIDResource::try_from(format!("{}#{}", &self.0, self.multibase())).expect(
            "programmer error: this should not be possible due to validation in the constructor",
        )
    }
    pub fn to_pub_key(&self) -> mbc::MBPubKey {
        mbc::MBPubKey::try_from(self.multibase()).expect(
            "programmer error: this should not be possible due to validation in the constructor",
        )
    }
    // TODO: Maybe &DIDStr itself should implement selfsign::Verifier
    pub fn to_verifier(&self) -> Box<dyn selfsign::Verifier> {
        let pub_key = self.to_pub_key();
        let pub_key_decoded = pub_key.decoded().unwrap();
        match pub_key_decoded.codec() {
            ssi_multicodec::ED25519_PUB => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    Box::new(ed25519_dalek::VerifyingKey::try_from(pub_key_decoded.data()).unwrap())
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("ed25519 key type not supported (ed25519-dalek cargo feature must be enabled)");
                }
            }
            ssi_multicodec::SECP256K1_PUB => {
                #[cfg(feature = "k256")]
                {
                    Box::new(k256::ecdsa::VerifyingKey::try_from(pub_key_decoded.data()).unwrap())
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!("secp256k1 key type not supported (k256 cargo feature must be enabled)");
                }
            }
            _ => panic!("programmer error: unsupported codec"),
        }
    }
    #[cfg(feature = "ed25519-dalek")]
    pub fn to_ed25519(&self) -> Result<ed25519_dalek::VerifyingKey> {
        let pub_key = self.to_pub_key();
        let pub_key_decoded = pub_key.decoded().unwrap();
        anyhow::ensure!(
            pub_key_decoded.codec() == ssi_multicodec::ED25519_PUB,
            "this did:key is not ed25519"
        );
        anyhow::ensure!(
            pub_key_decoded.data().len() == 32,
            "malformed ed25519 did:key value: invalid length"
        );
        let verifier = ed25519_dalek::VerifyingKey::try_from(pub_key_decoded.data()).unwrap();
        Ok(verifier)
    }
    #[cfg(feature = "k256")]
    pub fn to_secp256k1(&self) -> Result<k256::ecdsa::VerifyingKey> {
        let pub_key = self.to_pub_key();
        let pub_key_decoded = pub_key.decoded().unwrap();
        anyhow::ensure!(
            pub_key_decoded.codec() == ssi_multicodec::SECP256K1_PUB,
            "this did:key is not secp256k1"
        );
        anyhow::ensure!(
            pub_key_decoded.data().len() == 33,
            "malformed secp256k1 did:key value: invalid length"
        );
        let verifier = k256::ecdsa::VerifyingKey::try_from(pub_key_decoded.data()).unwrap();
        Ok(verifier)
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
        let pub_key =
            mbc::MBPubKeyStr::new_ref(data.strip_prefix("did:key:").unwrap()).map_err(|e| {
                anyhow::anyhow!("malformed did:key value: multibase decode failed: {}", e)
            })?;
        let pub_key_decoded = pub_key.decoded().unwrap();
        match pub_key_decoded.codec() {
            ssi_multicodec::ED25519_PUB => {
                anyhow::ensure!(
                    pub_key_decoded.data().len() == 32,
                    "malformed ed25519 did:key value: invalid length"
                );
            }
            ssi_multicodec::SECP256K1_PUB => {
                anyhow::ensure!(
                    pub_key_decoded.data().len() == 33,
                    "malformed secp256k1 did:key value: invalid length"
                );
                // TODO: Additional validation?
            }
            ssi_multicodec::P256_PUB => {
                anyhow::ensure!(
                    pub_key_decoded.data().len() == 33,
                    "malformed p256 did:key value: invalid length"
                );
                // TODO: Additional validation?
            }
            _ => anyhow::bail!("Unknown (and therefore unsupported) key type"),
        }
        Ok(())
    }
}
