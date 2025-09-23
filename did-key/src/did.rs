use crate::{DIDStr, Error};

#[derive(Clone, Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_did_key_str", borrow = "DIDStr")]
#[cfg_attr(feature = "serde", pneu_string(deserialize, serialize))]
pub struct DID(String);

impl TryFrom<&mbx::MBPubKeyStr> for DID {
    type Error = Error;
    fn try_from(pub_key: &mbx::MBPubKeyStr) -> Result<Self, Self::Error> {
        Ok(Self(format!("did:key:{}", pub_key.as_str())))
    }
}

impl TryFrom<&signature_dyn::VerifierBytes<'_>> for DID {
    type Error = Error;
    fn try_from(verifier_bytes: &signature_dyn::VerifierBytes<'_>) -> Result<Self, Self::Error> {
        let pub_key = mbx::MBPubKey::try_from_verifier_bytes(mbx::Base::Base58Btc, verifier_bytes)
            .map_err(|e| anyhow::anyhow!("could not decode verifier bytes: {}", e))?;
        Ok(Self(format!("did:key:{}", pub_key.as_str())))
    }
}
