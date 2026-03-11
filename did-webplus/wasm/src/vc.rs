use crate::{DIDResolver, Result, WalletBasedSigner, date_to_offset_date_time, into_js_value};
use std::ops::Deref;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[wasm_bindgen]
pub fn new_unsigned_credential(
    additional_context_vo: Option<Vec<String>>,
    credential_id: String,
    issuance_date: js_sys::Date,
    expiration_date: js_sys::Date,
    credential_subject: JsValue,
) -> Result<JsValue> {
    tracing::debug!(
        "HIPPO new_unsigned_credential: issuance_date: {:?}, expiration_date: {:?}",
        issuance_date,
        expiration_date
    );
    let issuance_date = date_to_offset_date_time(issuance_date);
    tracing::debug!(
        "   HIPPO new_unsigned_credential: issuance_date: {:?}",
        issuance_date
    );
    let expiration_date = date_to_offset_date_time(expiration_date);
    tracing::debug!(
        "   HIPPO new_unsigned_credential: expiration_date: {:?}",
        expiration_date
    );
    let credential_subject: serde_json::Value =
        serde_wasm_bindgen::from_value(credential_subject).map_err(into_js_value)?;
    let unsigned_credential = did_webplus_ssi::new_unsigned_credential(
        additional_context_vo,
        credential_id.as_str(),
        issuance_date,
        expiration_date,
        credential_subject,
    );
    tracing::debug!(
        "HIPPO new_unsigned_credential: unsigned_credential: {:?}",
        unsigned_credential
    );
    Ok(serde_wasm_bindgen::to_value(&unsigned_credential).map_err(into_js_value)?)
}

#[wasm_bindgen]
pub async fn issue_vc_ldp(
    unsigned_credential_jsvalue: JsValue,
    wallet_based_signer: &WalletBasedSigner,
    did_resolver: &DIDResolver,
) -> Result<JsValue> {
    let unsigned_credential: serde_json::Value =
        serde_wasm_bindgen::from_value(unsigned_credential_jsvalue).map_err(into_js_value)?;
    let did_resolver_a = did_resolver.as_arc().clone();
    let vc_ldp = did_webplus_ssi::issue_vc_ldp(
        unsigned_credential,
        wallet_based_signer.deref(),
        did_resolver_a,
    )
    .await
    .map_err(into_js_value)?;
    Ok(serde_wasm_bindgen::to_value(&vc_ldp).map_err(into_js_value)?)
}

#[wasm_bindgen]
pub async fn verify_vc_ldp(vc_ldp_jsvalue: JsValue, did_resolver: &DIDResolver) -> Result<()> {
    let did_resolver_a = did_resolver.as_arc().clone();
    let vc_ldp: ssi_claims::data_integrity::DataIntegrity<
        ssi_claims::vc::v1::JsonCredential,
        ssi_claims::data_integrity::AnySuite,
    > = serde_wasm_bindgen::from_value(vc_ldp_jsvalue).map_err(into_js_value)?;
    let verification_r = did_webplus_ssi::verify_vc_ldp(&vc_ldp, did_resolver_a)
        .await
        .map_err(into_js_value)?;
    verification_r.map_err(into_js_value)?;
    Ok(())
}

#[wasm_bindgen]
pub async fn issue_vc_jwt(
    unsigned_credential_jsvalue: JsValue,
    wallet_based_signer: &WalletBasedSigner,
) -> Result<String> {
    let unsigned_credential: serde_json::Value =
        serde_wasm_bindgen::from_value(unsigned_credential_jsvalue).map_err(into_js_value)?;
    let vc_jwt = did_webplus_ssi::issue_vc_jwt(unsigned_credential, wallet_based_signer.deref())
        .await
        .map_err(into_js_value)?;
    Ok(vc_jwt.into_string())
}

#[wasm_bindgen]
pub async fn verify_vc_jwt(vc_jwt: String, did_resolver: &DIDResolver) -> Result<()> {
    let did_resolver_a = did_resolver.as_arc().clone();
    let vc_jwt = ssi_jws::JwsBuf::new(vc_jwt).map_err(into_js_value)?;
    let verification_r = did_webplus_ssi::verify_vc_jwt(&vc_jwt, did_resolver_a)
        .await
        .map_err(into_js_value)?;
    verification_r.map_err(into_js_value)?;
    Ok(())
}
