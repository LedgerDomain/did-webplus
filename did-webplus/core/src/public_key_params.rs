use crate::{Error, PublicKeyParamsEC, PublicKeyParamsOKP};

// Note that this will use the "kty" field in serde to determine the variant of the enum.
#[derive(Clone, Debug, serde::Deserialize, Eq, derive_more::From, PartialEq, serde::Serialize)]
#[serde(tag = "kty")]
pub enum PublicKeyParams {
    EC(PublicKeyParamsEC),
    OKP(PublicKeyParamsOKP),
}

impl From<&mbc::MBPubKey> for PublicKeyParams {
    fn from(pub_key: &mbc::MBPubKey) -> Self {
        use std::ops::Deref;
        Self::from(pub_key.deref())
    }
}

impl From<&mbc::MBPubKeyStr> for PublicKeyParams {
    fn from(pub_key: &mbc::MBPubKeyStr) -> Self {
        let decoded = pub_key.decoded().unwrap();
        match decoded.codec() {
            ssi_multicodec::ED25519_PUB => PublicKeyParamsOKP::try_from(pub_key)
                .expect("programmer error")
                .into(),
            ssi_multicodec::SECP256K1_PUB => PublicKeyParamsEC::try_from(pub_key)
                .expect("programmer error")
                .into(),
            _ => panic!("programmer error: unsupported codec"),
        }
    }
}

impl TryFrom<&PublicKeyParams> for mbc::MBPubKey {
    type Error = Error;
    fn try_from(public_key_params: &PublicKeyParams) -> Result<Self, Self::Error> {
        match public_key_params {
            PublicKeyParams::EC(public_key_params_ec) => public_key_params_ec.try_into(),
            PublicKeyParams::OKP(public_key_params_okp) => public_key_params_okp.try_into(),
        }
    }
}
