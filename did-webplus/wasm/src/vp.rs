use crate::{
    DIDResolver, IssueVPParameters, Result, WalletBasedSigner, date_to_offset_date_time,
    into_js_value,
};
use std::ops::Deref;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

// This doesn't need to be public because it's only for converting to/from serde_json::Value and wasm_bindgen::JsValue.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedPresentation {
    #[serde(rename = "@context")]
    context: Vec<String>,
    id: String,
    #[serde(rename = "type")]
    r#type: String,
    #[serde(
        rename = "issuanceDate",
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    issuance_date_o: Option<time::OffsetDateTime>,
    #[serde(
        rename = "expirationDate",
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    expiration_date_o: Option<time::OffsetDateTime>,
    verifiable_credential: Vec<serde_json::Value>,
}

/// Note that issuance_date and expiration_date are only supported for JWT-formatted VPs.
#[wasm_bindgen]
pub fn new_unsigned_presentation(
    additional_context_vo: Option<Vec<String>>,
    presentation_id: String,
    issuance_date_o: Option<js_sys::Date>,
    expiration_date_o: Option<js_sys::Date>,
    verifiable_credential_jsvalue_vo: Option<Vec<JsValue>>,
) -> Result<JsValue> {
    let mut context_v = vec!["https://www.w3.org/2018/credentials/v1".to_string()];
    if let Some(additional_context_v) = additional_context_vo {
        context_v.extend(additional_context_v);
    }
    let issuance_date_o = issuance_date_o.map(date_to_offset_date_time);
    let expiration_date_o = expiration_date_o.map(date_to_offset_date_time);
    let mut verifiable_credential_v: Vec<serde_json::Value> = Vec::with_capacity(
        verifiable_credential_jsvalue_vo
            .as_ref()
            .map(Vec::len)
            .unwrap_or(0),
    );
    if let Some(verifiable_credential_jsvalue_v) = verifiable_credential_jsvalue_vo {
        for vc_jsvalue in verifiable_credential_jsvalue_v {
            verifiable_credential_v.push(
                serde_wasm_bindgen::from_value::<serde_json::Value>(vc_jsvalue)
                    .map_err(into_js_value)?,
            );
        }
    }
    let unsigned_presentation = UnsignedPresentation {
        context: context_v,
        id: presentation_id,
        r#type: "VerifiablePresentation".to_string(),
        issuance_date_o,
        expiration_date_o,
        verifiable_credential: verifiable_credential_v,
    };
    Ok(serde_wasm_bindgen::to_value(&unsigned_presentation)?)
}

/// Issue an LDP-formatted VP (a JSON blob).  Use new_unsigned_presentation to create the content of the presentation.
#[wasm_bindgen]
pub async fn issue_vp_ldp(
    unsigned_presentation_jsvalue: JsValue,
    issue_vp_parameters: IssueVPParameters,
    wallet_based_signer: &WalletBasedSigner,
    did_resolver: &DIDResolver,
) -> Result<JsValue> {
    let unsigned_presentation_value: serde_json::Value =
        serde_wasm_bindgen::from_value(unsigned_presentation_jsvalue).map_err(into_js_value)?;
    let unsigned_presentation: ssi_claims::vc::v1::JsonPresentation<serde_json::Value> =
        serde_json::from_value(unsigned_presentation_value).map_err(into_js_value)?;
    let issue_vp_parameters = issue_vp_parameters.into();
    let did_resolver_a = did_resolver.as_arc().clone();
    let vp_ldp = did_webplus_ssi::issue_vp_ldp(
        unsigned_presentation,
        issue_vp_parameters,
        wallet_based_signer.deref(),
        did_resolver_a,
    )
    .await
    .map_err(into_js_value)?;
    Ok(serde_wasm_bindgen::to_value(&vp_ldp).map_err(into_js_value)?)
}

/// Verify an LDP-formatted VP (a JSON blob), returning an error if the verification fails.  NOTE: This
/// does NOT also verify the credentials it contains.  Verifying credentials is its own complex procedure,
/// so it must be done separately and explicitly.  See verify_vc_jwt and verify_vc_ldp.
#[wasm_bindgen]
pub async fn verify_vp_ldp(vp_ldp_jsvalue: JsValue, did_resolver: &DIDResolver) -> Result<()> {
    let did_resolver_a = did_resolver.as_arc().clone();
    let vp_ldp: ssi_claims::data_integrity::DataIntegrity<
        ssi_claims::vc::v1::JsonPresentation<
            ssi_claims::JsonCredentialOrJws<ssi_claims::data_integrity::AnySuite>,
        >,
        ssi_claims::data_integrity::AnySuite,
    > = serde_wasm_bindgen::from_value(vp_ldp_jsvalue).map_err(into_js_value)?;
    let verification_r = did_webplus_ssi::verify_vp_ldp(&vp_ldp, did_resolver_a)
        .await
        .map_err(into_js_value)?;
    verification_r.map_err(into_js_value)?;
    Ok(())
}

/// Issue a JWT-formatted VP.  Use new_unsigned_presentation to create the content of the presentation.
#[wasm_bindgen]
pub async fn issue_vp_jwt(
    unsigned_presentation_jsvalue: JsValue,
    issue_vp_parameters: IssueVPParameters,
    wallet_based_signer: &WalletBasedSigner,
) -> Result<String> {
    let unsigned_presentation_value: serde_json::Value =
        serde_wasm_bindgen::from_value(unsigned_presentation_jsvalue).map_err(into_js_value)?;
    let unsigned_presentation: ssi_claims::vc::v1::JsonPresentation<serde_json::Value> =
        serde_json::from_value(unsigned_presentation_value).map_err(into_js_value)?;
    let issue_vp_parameters = issue_vp_parameters.into();
    let vp_jwt = did_webplus_ssi::issue_vp_jwt(
        unsigned_presentation,
        issue_vp_parameters,
        wallet_based_signer.deref(),
    )
    .await
    .map_err(into_js_value)?;
    Ok(vp_jwt.into_string())
}

/// Verify a JWT-formatted VP, returning an error if the verification fails.  NOTE: This
/// does NOT also verify the credentials it contains.  Verifying credentials is its own complex procedure,
/// so it must be done separately and explicitly.  See verify_vc_jwt and verify_vc_ldp.
#[wasm_bindgen]
pub async fn verify_vp_jwt(vp_jwt: String, did_resolver: &DIDResolver) -> Result<()> {
    let did_resolver_a = did_resolver.as_arc().clone();
    let vp_jwt: ssi_jws::JwsBuf = ssi_jws::JwsBuf::new(vp_jwt).map_err(into_js_value)?;
    let verification_r = did_webplus_ssi::verify_vp_jwt(&vp_jwt, did_resolver_a)
        .await
        .map_err(into_js_value)?;
    verification_r.map_err(into_js_value)?;
    Ok(())
}
