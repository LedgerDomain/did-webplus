use std::{str::FromStr, sync::Arc};

use crate::{pick_suite_for_did_webplus_by_id, DIDWebplus, Result};

pub fn new_unsigned_presentation(
    id_o: Option<&str>,
    verifiable_credentials_v: Vec<serde_json::Value>,
) -> Result<ssi_claims::vc::v1::JsonPresentation<serde_json::Value>> {
    let id_o = id_o.map(|id| FromStr::from_str(id)).transpose()?;
    Ok(ssi_claims::vc::v1::JsonPresentation::new(
        id_o,
        None,
        verifiable_credentials_v,
    ))
}

pub struct IssueVPParameters {
    pub challenge_o: Option<String>,
    pub domains_vo: Option<Vec<String>>,
    pub nonce_o: Option<String>,
}

pub async fn issue_vp_ldp<C: serde::Serialize, W: did_webplus_wallet::Wallet + Clone>(
    mut unsigned_presentation: ssi_claims::vc::v1::JsonPresentation<C>,
    issue_vp_parameters: IssueVPParameters,
    wallet_based_signer: &did_webplus_wallet::WalletBasedSigner<W>,
    did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
) -> Result<
    ssi_claims::data_integrity::DataIntegrity<
        ssi_claims::vc::v1::JsonPresentation<C>,
        ssi_claims::data_integrity::AnySuite,
    >,
> {
    anyhow::ensure!(
        unsigned_presentation.holder.is_none(),
        "holder field of unsigned_presentation must not be set before signing"
    );

    unsigned_presentation.holder = Some(
        wallet_based_signer
            .key_fully_qualified()
            .to_string()
            .try_into()?,
    );

    // // SEE: <https://www.w3.org/TR/2022/REC-vc-data-model-20220303/#jwt-encoding> for the JWT field mapping.
    // {
    //     // TEMP HACK -- to see what fields actually appear in the VP.
    //     let issuance_date = time::OffsetDateTime::now_utc();
    //     let expiration_date = issuance_date + time::Duration::days(1);
    //     unsigned_presentation.additional_properties.insert(
    //         "issuanceDate".to_string(),
    //         issuance_date
    //             .format(&time::format_description::well_known::Rfc3339)
    //             .unwrap()
    //             .into(),
    //     );
    //     // unsigned_presentation.additional_properties.insert(
    //     //     "expirationDate".to_string(),
    //     //     expiration_date
    //     //         .format(&time::format_description::well_known::Rfc3339)
    //     //         .unwrap()
    //     //         .into(),
    //     // );

    //     // if let Some(challenge) = issue_vp_parameters.challenge_o {
    //     //     unsigned_presentation
    //     //         .additional_properties
    //     //         .insert("challenge".to_string(), challenge.into());
    //     // }
    //     // if let Some(domains_v) = issue_vp_parameters.domains_vo {
    //     //     for domain in domains_v {
    //     //         unsigned_presentation
    //     //             .additional_properties
    //     //             .insert("audience".to_string(), domain.into());
    //     //     }
    //     // }
    //     // if let Some(nonce) = issue_vp_parameters.nonce_o {
    //     //     unsigned_presentation
    //     //         .additional_properties
    //     //         .insert("nonce".to_string(), nonce.into());
    //     // }
    // }

    let did_resolver = DIDWebplus { did_resolver_a };
    use ssi_dids::DIDResolver;
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyMethod>();

    let proof_options = {
        let did_url =
            ssi_dids::DIDURLBuf::from_string(wallet_based_signer.key_fully_qualified().to_string())
                .expect("pass");
        // Verification method as IRI reference (resolver will resolve when needed).
        let verification_method = ssi_verification_methods::ReferenceOrOwned::<
            ssi_verification_methods::AnyMethod,
        >::from(did_url.clone().into_iri());

        let mut proof_options =
            ssi_claims::data_integrity::ProofOptions::from_method(verification_method);
        proof_options.proof_purpose = ssi_verification_methods::ProofPurpose::Authentication;
        proof_options.challenge = issue_vp_parameters.challenge_o;
        if let Some(domains_v) = issue_vp_parameters.domains_vo {
            proof_options.domains.extend(domains_v);
        }
        proof_options.nonce = issue_vp_parameters.nonce_o;
        proof_options
    };

    // Pick a suitable Data-Integrity signature suite for did:webplus (no JWK needed).
    let cryptosuite =
        pick_suite_for_did_webplus_by_id(wallet_based_signer.key_fully_qualified().as_str())
            .ok_or_else(|| anyhow::anyhow!("could not find appropriate cryptosuite"))?;

    use ssi_claims::data_integrity::CryptographicSuite;
    Ok(cryptosuite
        .sign(
            unsigned_presentation,
            &vm_resolver,
            &wallet_based_signer,
            proof_options,
        )
        .await?)
}

pub async fn verify_vp_ldp<C>(
    vp_ldp: &ssi_claims::data_integrity::DataIntegrity<
        ssi_claims::vc::v1::JsonPresentation<C>,
        ssi_claims::data_integrity::AnySuite,
    >,
    did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
) -> Result<ssi_claims::Verification>
where
    C: serde::Serialize,
{
    let did_resolver = DIDWebplus { did_resolver_a };
    // Also add the did:key resolver.
    let did_resolver = (did_resolver, ssi_dids::DIDKey);
    use ssi_dids::DIDResolver;
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyMethod>();
    let verification_params = ssi_claims::VerificationParameters::from_resolver(&vm_resolver);
    Ok(vp_ldp.verify(&verification_params).await?)
}

pub async fn issue_vp_jwt<C: serde::Serialize, W: did_webplus_wallet::Wallet>(
    mut unsigned_presentation: ssi_claims::vc::v1::JsonPresentation<C>,
    issue_vp_parameters: IssueVPParameters,
    wallet_based_signer: &did_webplus_wallet::WalletBasedSigner<W>,
) -> Result<ssi_jws::JwsBuf> {
    anyhow::ensure!(
        unsigned_presentation.holder.is_none(),
        "holder field of unsigned_presentation must not be set before signing"
    );

    unsigned_presentation.holder = Some(
        wallet_based_signer
            .key_fully_qualified()
            .to_string()
            .try_into()?,
    );

    // SEE: <https://www.w3.org/TR/2022/REC-vc-data-model-20220303/#jwt-encoding> for the JWT field mapping.
    {
        // TEMP HACK -- to see if this causes nbf, exp, and/or iat to be set.
        let issuance_date = time::OffsetDateTime::now_utc();
        let expiration_date = issuance_date + time::Duration::days(1);
        unsigned_presentation.additional_properties.insert(
            "issuanceDate".to_string(),
            issuance_date
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
                .into(),
        );
        unsigned_presentation.additional_properties.insert(
            "expirationDate".to_string(),
            expiration_date
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
                .into(),
        );
        if let Some(challenge) = issue_vp_parameters.challenge_o {
            unsigned_presentation
                .additional_properties
                .insert("challenge".to_string(), challenge.into());
        }
        if let Some(domains_v) = issue_vp_parameters.domains_vo {
            for domain in domains_v {
                unsigned_presentation
                    .additional_properties
                    .insert("audience".to_string(), domain.into());
            }
        }
        if let Some(nonce) = issue_vp_parameters.nonce_o {
            unsigned_presentation
                .additional_properties
                .insert("nonce".to_string(), nonce.into());
        }
    }

    use ssi_claims::vc::v1::ToJwtClaims;
    use ssi_jws::JwsPayload;
    Ok(unsigned_presentation
        .to_jwt_claims()
        .unwrap()
        .sign(&wallet_based_signer)
        .await?)
}

/// This verifies the VP, but not the credentials it contains.  Verifying credentials is its own complex procedure,
/// so it should be done separately and explicitly.
// TODO: Accept a vm_resolver so that multiple DID methods could be supported.
pub async fn verify_vp_jwt(
    vp_jwt: &ssi_jws::JwsBuf,
    did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
) -> Result<ssi_claims::Verification> {
    let did_resolver = DIDWebplus { did_resolver_a };
    // Also add the did:key resolver.
    let did_resolver = (did_resolver, ssi_dids::DIDKey);
    use ssi_dids::DIDResolver;
    let vm_resolver = did_resolver.into_vm_resolver::<ssi_verification_methods::AnyMethod>();
    let verification_params = ssi_claims::VerificationParameters::from_resolver(&vm_resolver);
    Ok(vp_jwt.verify(&verification_params).await?)
}
