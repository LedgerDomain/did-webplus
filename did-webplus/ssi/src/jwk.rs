use crate::Result;
use did_webplus_core::{DIDStr, KeyPurpose};
use did_webplus_wallet::Wallet;
use did_webplus_wallet_store::{
    LocallyControlledVerificationMethodFilter, VerificationMethodRecord,
};

/// This will get the appropriate signing key from the wallet for the given DID, key purpose, and key ID.
/// If there is no unique key that matches the filter arguments, then an error will be returned.
/// If key_id_o is specified, then a match will always only return a single verification method record.
pub async fn get_signing_jwk(
    wallet: &dyn Wallet,
    did: &DIDStr,
    key_purpose: KeyPurpose,
    key_id_o: Option<&str>,
    http_options_o: Option<&did_webplus_core::HTTPOptions>,
) -> Result<(VerificationMethodRecord, ssi_jwk::JWK)> {
    // Ensure that the Wallet has fetched the latest DID document for the DID being used to sign.
    wallet.fetch_did(did, http_options_o).await?;
    // Get the appropriate signing key.
    let verification_method_record_v = wallet
        .get_locally_controlled_verification_methods(&LocallyControlledVerificationMethodFilter {
            did_o: Some(did.to_owned()),
            key_purpose_o: Some(key_purpose),
            // version_id_o: Some(did.query_version_id()),
            version_id_o: None,
            key_id_o: key_id_o.map(|key_id| key_id.to_owned()),
            result_limit_o: None,
        })
        .await?;
    // If there is more than one verification method record, then there's no way to proceed.  The key_id_o must be specified.
    if verification_method_record_v.len() > 1 {
        anyhow::bail!("Multiple verification method records found for filter arguments -- Must specify key_id_o to select a unique key.");
    }
    let (verification_method_record, signer_bytes) =
        verification_method_record_v.into_iter().next().unwrap();

    let priv_jwk = signer_bytes_to_ssi_jwk(
        Some(
            verification_method_record
                .did_key_resource_fully_qualified
                .to_string()
                .as_str(),
        ),
        &signer_bytes,
    )?;
    Ok((verification_method_record, priv_jwk))
}

// This is a TEMP HACK -- it shouldn't be necessary to extract the private key into JWK form in order to use it
// to sign things in the ssi crate.
fn signer_bytes_to_ssi_jwk(
    kid_o: Option<&str>,
    signer_bytes: &signature_dyn::SignerBytes<'_>,
) -> Result<ssi_jwk::JWK> {
    match signer_bytes.key_type() {
        signature_dyn::KeyType::Ed25519 => {
            #[cfg(feature = "ed25519-dalek")]
            {
                let secret_key = ed25519_dalek::SecretKey::try_from(signer_bytes.bytes())
                    .expect("this should not fail because of check in new");
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
                let verifying_key = signing_key.verifying_key();
                let mut jwk = ssi_jwk::JWK::from(ssi_jwk::Params::OKP(ssi_jwk::OctetParams {
                    curve: "Ed25519".to_string(),
                    public_key: ssi_jwk::Base64urlUInt(verifying_key.to_bytes().to_vec()),
                    private_key: Some(ssi_jwk::Base64urlUInt(signing_key.to_bytes().to_vec())),
                }));
                if let Some(kid_o) = kid_o {
                    jwk.key_id = Some(kid_o.to_string());
                }
                jwk.algorithm = Some(ssi_jwk::algorithm::Algorithm::EdDSA);
                Ok(jwk)
            }
            #[cfg(not(feature = "ed25519-dalek"))]
            {
                panic!("ed25519-dalek feature not enabled");
            }
        }
        signature_dyn::KeyType::Secp256k1 => {
            #[cfg(feature = "k256")]
            {
                let signing_key = k256::ecdsa::SigningKey::from_slice(signer_bytes.bytes())
                    .expect("this should not fail because of check in new");
                let secret_key = k256::SecretKey::from(signing_key);
                let public_key = secret_key.public_key();
                let mut ec_params = ssi_jwk::ECParams::from(&public_key);
                ec_params.ecc_private_key =
                    Some(ssi_jwk::Base64urlUInt(signer_bytes.bytes().to_vec()));
                let mut jwk = ssi_jwk::JWK::from(ssi_jwk::Params::EC(ec_params));
                if let Some(kid_o) = kid_o {
                    jwk.key_id = Some(kid_o.to_string());
                }
                // jwk.algorithm = Some(ssi_jwk::algorithm::Algorithm::ES256);
                Ok(jwk)
            }
            #[cfg(not(feature = "k256"))]
            {
                panic!("k256 feature not enabled");
            }
        }
        _ => anyhow::bail!("unsupported key type: {:?}", signer_bytes.key_type()),
    }
}
