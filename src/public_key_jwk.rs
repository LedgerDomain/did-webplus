use crate::{DIDWithKeyIdFragment, Error, PublicKeyParams, DID};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct PublicKeyJWK {
    // TODO: kid field is optional; consider taking this out to simplify things.
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid_o: Option<DIDWithKeyIdFragment>,
    // Note that this will use the "kty" field in serde to determine the variant of the enum.
    #[serde(flatten)]
    pub public_key_params: PublicKeyParams,
}

impl PublicKeyJWK {
    pub fn try_from_did_and_verifier(did: &DID, verifier: &dyn selfsign::Verifier) -> Self {
        let keri_verifier = verifier.to_keri_verifier();
        let public_key_params = PublicKeyParams::from(verifier);
        assert!(
            selfsign::KERIVerifier::try_from(&public_key_params).expect("programmer error")
                == keri_verifier,
            "sanity check"
        );
        let kid = did.with_fragment(keri_verifier);
        Self {
            kid_o: Some(kid),
            public_key_params,
        }
    }
}

impl TryFrom<&PublicKeyJWK> for selfsign::KERIVerifier {
    type Error = Error;
    fn try_from(public_key_jwk: &PublicKeyJWK) -> Result<Self, Self::Error> {
        let keri_verifier = selfsign::KERIVerifier::try_from(&public_key_jwk.public_key_params)?;
        // Verify that the kid fragment matches the KERIVerifier corresponding to the key material.
        if let Some(kid) = &public_key_jwk.kid_o {
            if *kid.fragment != keri_verifier {
                return Err(Error::Malformed(
                    "publicKeyJwk kid fragment does not match publicKeyJwk key material",
                ));
            }
        }
        Ok(keri_verifier)
    }
}
