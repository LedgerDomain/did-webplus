use std::sync::Arc;

use crate::{pick_suite_for_did_webplus_by_id, DIDWebplus, Result};

pub fn new_unsigned_credential(
    additional_context_vo: Option<Vec<String>>,
    credential_id: &str,
    issuance_date: time::OffsetDateTime,
    expiration_date: time::OffsetDateTime,
    credential_subject: serde_json::Value,
) -> serde_json::Value {
    let mut context_v = vec!["https://www.w3.org/2018/credentials/v1".to_string()];
    if let Some(additional_context_v) = additional_context_vo {
        context_v.extend(additional_context_v);
    }
    serde_json::json!({
        "@context": context_v,
        "type": "VerifiableCredential",
        "id": credential_id,
        "issuanceDate": xsd_types::DateTime::from(issuance_date),
        "expirationDate": xsd_types::DateTime::from(expiration_date),
        "credentialSubject": credential_subject
    })
}

pub async fn issue_vc_ldp<W: did_webplus_wallet::Wallet + Clone>(
    mut unsigned_credential: serde_json::Value,
    wallet_based_signer: &did_webplus_wallet::WalletBasedSigner<W>,
    did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
) -> Result<
    ssi_claims::data_integrity::DataIntegrity<
        ssi_claims::vc::v1::JsonCredential,
        ssi_claims::data_integrity::AnySuite,
    >,
> {
    anyhow::ensure!(
        unsigned_credential.is_object(),
        "unsigned_credential must be a serde_json::Value::Object"
    );
    anyhow::ensure!(
        unsigned_credential
            .as_object()
            .unwrap()
            .get("issuer")
            .is_none(),
        "issuer field of unsigned_credential must not be set before signing"
    );

    // Create a verification method resolver, which will be in charge of decoding the DID back into a public key.
    let did_resolver = DIDWebplus { did_resolver_a };
    use ssi_dids::DIDResolver;
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyMethod>();

    // Create the DID URL which fully qualifies the specific key to be used.
    let issuer_did_url =
        ssi_dids::DIDURLBuf::from_string(wallet_based_signer.key_fully_qualified().to_string())?;
    // Verification method as IRI reference (resolver will resolve when needed).
    let verification_method = ssi_verification_methods::ReferenceOrOwned::<
        ssi_verification_methods::AnyMethod,
    >::from(issuer_did_url.clone().into_iri());

    // Pick a suitable Data-Integrity signature suite for did:webplus (no JWK needed).
    let cryptosuite = pick_suite_for_did_webplus_by_id(issuer_did_url.as_str())
        .ok_or_else(|| anyhow::anyhow!("could not find appropriate cryptosuite"))?;

    // Set the issuer field based on the WalletBasedSigner.
    unsigned_credential.as_object_mut().unwrap().insert(
        "issuer".to_string(),
        serde_json::Value::String(issuer_did_url.to_string()),
    );
    let json_credential: ssi_claims::vc::v1::JsonCredential =
        serde_json::from_value(unsigned_credential)?;
    tracing::debug!("json_credential: {:?}", json_credential);

    use ssi_claims::data_integrity::CryptographicSuite;
    Ok(cryptosuite
        .sign(
            json_credential,
            &vm_resolver,
            &wallet_based_signer,
            ssi_claims::data_integrity::ProofOptions::from_method(verification_method.clone()),
        )
        .await?)
}

/// Verify an LDP-formatted VC.  Note that this does not do any revocation status checking, or credential-type-specific verification.
pub async fn verify_vc_ldp(
    vc_ldp: &ssi_claims::data_integrity::DataIntegrity<
        ssi_claims::vc::v1::JsonCredential,
        ssi_claims::data_integrity::AnySuite,
    >,
    did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
) -> Result<ssi_claims::Verification> {
    let did_resolver = DIDWebplus { did_resolver_a };
    // Also add the did:key resolver.
    let did_resolver = (did_resolver, ssi_dids::DIDKey);
    use ssi_dids::DIDResolver;
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyMethod>();
    let verification_params = ssi_claims::VerificationParameters::from_resolver(&vm_resolver);
    Ok(vc_ldp.verify(&verification_params).await?)
}

pub async fn issue_vc_jwt<W: did_webplus_wallet::Wallet>(
    mut unsigned_credential: serde_json::Value,
    wallet_based_signer: &did_webplus_wallet::WalletBasedSigner<W>,
) -> Result<ssi_jws::JwsBuf> {
    anyhow::ensure!(
        unsigned_credential.is_object(),
        "unsigned_credential must be a serde_json::Value::Object"
    );
    anyhow::ensure!(
        unsigned_credential
            .as_object()
            .unwrap()
            .get("issuer")
            .is_none(),
        "issuer field of unsigned_credential must not be set before signing"
    );

    unsigned_credential.as_object_mut().unwrap().insert(
        "issuer".to_string(),
        serde_json::Value::String(wallet_based_signer.key_fully_qualified().to_string()),
    );
    let json_credential: ssi_claims::vc::v1::JsonCredential =
        serde_json::from_value(unsigned_credential)?;

    use ssi_claims::{vc::v1::ToJwtClaims, JwsPayload};
    Ok(json_credential
        .to_jwt_claims()
        .unwrap()
        .sign(wallet_based_signer)
        .await?)
}

/// Verify a JWT-formatted VC.  Note that this does not do any revocation status checking, or credential-type-specific verification.
// TODO: Accept a vm_resolver so that multiple DID methods could be supported.
pub async fn verify_vc_jwt(
    vc_jwt: &ssi_jws::JwsBuf,
    did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
) -> Result<ssi_claims::Verification> {
    let did_resolver = DIDWebplus { did_resolver_a };
    // Also add the did:key resolver.
    let did_resolver = (did_resolver, ssi_dids::DIDKey);
    use ssi_dids::DIDResolver;
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyMethod>();
    let verification_params = ssi_claims::VerificationParameters::from_resolver(&vm_resolver);
    Ok(vc_jwt.verify(&verification_params).await?)
}
