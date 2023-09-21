use std::borrow::Cow;

use crate::PublicKeySet;

/// did:webplus-specific parameters for creating a root DID document in order to create a DID and its microledger.
#[derive(Debug)]
pub struct DIDDocumentCreateParams<'a> {
    pub did_webplus_host: Cow<'a, str>,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    pub public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
}
