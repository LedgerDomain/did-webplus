use crate::{DIDResource, Error, Result};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", pneu_str(deserialize, serialize))]
#[repr(transparent)]
pub struct DIDStr(str);

impl DIDStr {
    /// This returns the method-specific value, which for did:key is a multibase string that
    /// directly encodes the public key being represented.
    pub fn multibase(&self) -> &str {
        self.0.strip_prefix("did:key:").expect(
            "programmer error: this should not be possible due to validation in the constructor",
        )
    }
    pub fn with_fragment(&self) -> DIDResource {
        DIDResource::try_from(format!("{}#{}", &self.0, self.multibase())).expect(
            "programmer error: this should not be possible due to validation in the constructor",
        )
    }
    pub fn as_mb_pub_key(&self) -> &mbx::MBPubKeyStr {
        mbx::MBPubKeyStr::new_ref(self.multibase()).expect(
            "programmer error: this should not be possible due to validation in the constructor",
        )
    }
    pub fn to_verifier_bytes(&self) -> signature_dyn::VerifierBytes {
        signature_dyn::VerifierBytes::try_from(self.as_mb_pub_key()).expect(
            "programmer error: this should not be possible due to validation in the constructor",
        )
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
        mbx::MBPubKeyStr::validate(data.strip_prefix("did:key:").unwrap()).map_err(|e| {
            anyhow::anyhow!("malformed did:key value: multibase decode failed: {}", e)
        })?;
        Ok(())
    }
}
