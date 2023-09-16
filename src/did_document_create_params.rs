use std::borrow::Cow;

use crate::PublicKeySet;

/// Parameters needed for creating a root DID document.
#[derive(Debug)]
pub struct DIDDocumentCreateParams<'a> {
    pub did_webplus_host: Cow<'a, str>,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    pub public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
}
