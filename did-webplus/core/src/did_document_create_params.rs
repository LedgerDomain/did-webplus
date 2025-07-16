use std::borrow::Cow;

use crate::PublicKeySet;

/// did:webplus-specific parameters for creating a root DID document in order to create a DID and its microledger.
#[derive(Debug)]
pub struct DIDDocumentCreateParams<'a> {
    pub did_hostname: Cow<'a, str>,
    pub did_port_o: Option<u16>,
    pub did_path_o: Option<Cow<'a, str>>,
    pub valid_from: time::OffsetDateTime,
    // TODO: Could have a planned expiration date for short-lived DID document durations.
    pub public_key_set: PublicKeySet<&'a dyn selfsign::Verifier>,
}
