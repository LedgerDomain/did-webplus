use crate::{DIDStr, Error};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[cfg_attr(feature = "serde", pneu_str(deserialize, serialize))]
#[repr(transparent)]
pub struct DIDResourceStr(str);

impl DIDResourceStr {
    pub fn did(&self) -> &DIDStr {
        let (did, _fragment) = self.0.split_once('#').expect("programmer error: this should not fail due to guarantees in construction of DIDResource");
        DIDStr::new_ref(did).expect("programmer error: this should not fail due to guarantees in construction of DIDResource")
    }
    pub fn fragment(&self) -> &str {
        let (_did, fragment) = self.0.split_once('#').expect("programmer error: this should not fail due to guarantees in construction of DIDResource");
        fragment
    }
}

impl pneutype::Validate for DIDResourceStr {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        let (did_str, fragment) = data
            .split_once('#')
            .ok_or_else(|| anyhow::anyhow!("Malformed DIDResource {:?}", data))?;
        let did = DIDStr::new_ref(did_str).map_err(|e| {
            anyhow::anyhow!(
                "Malformed base DID portion of DIDResource {:?}; error was: {}",
                data,
                e
            )
        })?;
        anyhow::ensure!(did.multibase() == fragment, "Malformed DIDResource {:?}; expected fragment to be identical to method-specific identifier {:?}", data, did.multibase());
        Ok(())
    }
}
