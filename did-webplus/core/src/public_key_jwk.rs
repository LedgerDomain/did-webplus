use crate::{DIDKeyResource, DIDStr, Error, PublicKeyParams};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyJWK {
    // TODO: kid field is optional; consider taking this out to simplify things.
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid_o: Option<DIDKeyResource>,
    // Note that this will use the "kty" field in serde to determine the variant of the enum.
    #[serde(flatten)]
    pub public_key_params: PublicKeyParams,
}

impl PublicKeyJWK {
    pub fn try_from_did_and_verifier(did: &DIDStr, verifier: &dyn selfsign::Verifier) -> Self {
        let keri_verifier = verifier.to_keri_verifier();
        let public_key_params = PublicKeyParams::from(verifier);
        assert!(
            selfsign::KERIVerifier::try_from(&public_key_params)
                .expect("programmer error")
                .as_keri_verifier_str()
                == keri_verifier.as_ref(),
            "sanity check"
        );
        let kid: DIDKeyResource = did.with_fragment(keri_verifier.as_ref());
        Self {
            kid_o: Some(kid),
            public_key_params,
        }
    }
}

impl TryFrom<&PublicKeyJWK> for selfsign::KERIVerifier {
    type Error = Error;
    fn try_from(public_key_jwk: &PublicKeyJWK) -> Result<Self, Self::Error> {
        Ok(selfsign::KERIVerifier::try_from(
            &public_key_jwk.public_key_params,
        )?)
    }
}
