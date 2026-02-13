use crate::Result;
use ssi_claims::jwt::ToDecodedJwt;

pub async fn sign_jwt<Claims: serde::Serialize, Signer: ssi_jws::JwsSigner>(
    claims: &ssi_claims::JWTClaims<Claims>,
    signer: &Signer,
) -> Result<ssi_claims::JwsBuf> {
    use ssi_claims::JwsPayload;
    Ok(claims.sign(signer).await?)
}

pub async fn verify_jwt<R: ssi_dids::DIDResolver>(
    jwt: &str,
    did_resolver: R,
) -> Result<ssi_jws::JwsBuf> {
    // Setup the verification parameters.
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyJwkMethod>();
    let params = ssi_claims::VerificationParameters::from_resolver(vm_resolver);
    // Not sure why using the borrowed version requires static lifetime for jwt,
    // so have to use the owned version here.
    let jwt = ssi_jws::JwsBuf::new(jwt.to_owned())?;
    jwt.verify_jwt(&params).await??;
    Ok(jwt)
}

pub async fn decode_jwt<C: serde::de::DeserializeOwned>(
    jwt: &ssi_jws::Jws,
) -> Result<ssi_jws::JwsParts<ssi_jwt::JWTClaims<C>>> {
    Ok(jwt.to_decoded_custom_jwt::<C>()?.into_jws())
}
