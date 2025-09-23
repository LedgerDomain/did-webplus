use crate::{DIDResourceStr, Error, DID};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuString)]
#[pneu_string(as_pneu_str = "as_did_resource_str", borrow = "DIDResourceStr")]
#[cfg_attr(feature = "serde", pneu_string(deserialize, serialize))]
pub struct DIDResource(String);

impl TryFrom<&signature_dyn::VerifierBytes<'_>> for DIDResource {
    type Error = Error;
    fn try_from(verifier_bytes: &signature_dyn::VerifierBytes<'_>) -> Result<Self, Self::Error> {
        // This allocates once more than is necessary, but whateva.
        Ok(DID::try_from(verifier_bytes)?.with_fragment())
    }
}
