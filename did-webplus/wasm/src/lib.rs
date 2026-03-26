mod did;
mod did_doc_store;
mod did_resolver;
mod http_headers_for;
mod http_options;
mod http_scheme_override;
mod issue_vp_parameters;
mod jws;
mod jwt;
mod key_purpose;
mod key_type;
mod locally_controlled_verification_method_filter;
mod mb_hash_function;
mod signer;
mod vc;
mod verification_method_record;
mod verifier_resolver;
mod vjson;
mod vjson_resolver;
mod vjson_store;
mod vp;
mod wallet;
mod wallet_based_signer;
mod wallet_record;

pub use crate::{
    did::DID,
    did_doc_store::DIDDocStore,
    did_resolver::{DIDResolver, did_resolve},
    http_headers_for::HTTPHeadersFor,
    http_options::HTTPOptions,
    http_scheme_override::HTTPSchemeOverride,
    issue_vp_parameters::IssueVPParameters,
    jws::{jws_sign, jws_verify},
    jwt::{jwt_sign, jwt_verify},
    key_purpose::{KeyPurpose, key_purpose_as_str},
    key_type::KeyType,
    locally_controlled_verification_method_filter::LocallyControlledVerificationMethodFilter,
    mb_hash_function::{Base, HashFunction, MBHashFunction},
    signer::Signer,
    vc::{issue_vc_jwt, issue_vc_ldp, new_unsigned_credential, verify_vc_jwt, verify_vc_ldp},
    verification_method_record::VerificationMethodRecord,
    verifier_resolver::VerifierResolver,
    vjson::{vjson_default_schema, vjson_self_hash, vjson_sign_and_self_hash, vjson_verify},
    vjson_resolver::VJSONResolver,
    vjson_store::VJSONStore,
    vp::{issue_vp_jwt, issue_vp_ldp, new_unsigned_presentation, verify_vp_jwt, verify_vp_ldp},
    wallet::{CreateDIDParameters, DeactivateDIDParameters, UpdateDIDParameters, Wallet},
    wallet_based_signer::WalletBasedSigner,
    wallet_record::WalletRecord,
};
pub type Error = JsValue;
pub type Result<T> = std::result::Result<T, JsValue>;

use wasm_bindgen::JsValue;

pub fn into_js_value<T: std::fmt::Display>(t: T) -> JsValue {
    JsValue::from(t.to_string())
}

/// This is the WebAssembly entry point.  It is used to initialize the logger.
/// It is only defined if the `define-start-function` feature is enabled.
#[cfg(feature = "define-start-function")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() -> Result<()> {
    console_error_panic_hook::set_once();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Debug));
    Ok(())
}

pub(crate) fn date_to_offset_date_time(date: js_sys::Date) -> time::OffsetDateTime {
    let year = date.get_full_year();
    assert!(year <= i32::MAX as u32);
    let year = year as i32;

    let month = date.get_month();
    assert!(month <= 11);
    let month = time::Month::try_from(month as u8).unwrap();

    let day = date.get_date();
    assert!(day >= 1 && day <= 31);
    let day = day as u8;

    let hour = date.get_hours();
    assert!(hour <= 23);
    let hour = hour as u8;

    let minute = date.get_minutes();
    assert!(minute <= 59);
    let minute = minute as u8;

    let second = date.get_seconds();
    assert!(second <= 59);
    let second = second as u8;

    let millisecond = date.get_milliseconds();
    assert!(millisecond <= 999);
    let millisecond = millisecond as u32;

    time::OffsetDateTime::new_utc(
        time::Date::from_calendar_date(year as i32, month, day).unwrap(),
        time::Time::from_hms_nano(hour, minute, second, millisecond * 1_000_000).unwrap(),
    )
}
