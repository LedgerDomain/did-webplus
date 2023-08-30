use crate::{DIDWebplus, VerificationMethod};

// TODO: Maybe make this an enum called DIDDocument instead for static dispatch.
pub trait DIDDocumentTrait {
    fn id(&self) -> &DIDWebplus;
    fn said(&self) -> &said::SelfAddressingIdentifier;
    fn prev_did_document_said_o(&self) -> Option<&said::SelfAddressingIdentifier>;
    fn valid_from(&self) -> &chrono::DateTime<chrono::Utc>;
    fn version_id(&self) -> u32;
    fn verification_method_v(&self) -> &[VerificationMethod];
    fn authentication_fragment_v(&self) -> &[String];
    fn assertion_fragment_v(&self) -> &[String];
    fn key_agreement_fragment_v(&self) -> &[String];
    fn capability_invocation_fragment_v(&self) -> &[String];
    fn capability_delegation_fragment_v(&self) -> &[String];
}
