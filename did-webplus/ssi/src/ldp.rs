use ssi_claims::data_integrity::AnySuite;
use ssi_verification_methods::VerificationMethod;

/// Picks the appropriate cryptographic suite for a did:webplus verification method.
///
/// This is used when signing LDP-format VCs and VPs without a JWK, since
/// `AnySuite::pick` requires a JWK to determine the algorithm.
///
/// For did:webplus, the suite is always `JsonWebSignature2020`.
pub fn pick_suite_for_did_webplus(
    verification_method: &ssi_verification_methods::AnyMethod,
) -> Option<AnySuite> {
    pick_suite_for_did_webplus_by_id(verification_method.id().as_str())
}

/// Picks the suite by verification method ID string (e.g. when you only have the key_id).
pub fn pick_suite_for_did_webplus_by_id(id: &str) -> Option<AnySuite> {
    if id.starts_with("did:webplus:") {
        Some(AnySuite::JsonWebSignature2020)
    } else {
        None
    }
}
