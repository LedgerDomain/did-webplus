mod did_document;
mod did_document_metadata;
mod did_uri_components;
mod did_webplus;
mod did_webplus_with_fragment;
mod did_webplus_with_query;
mod did_webplus_with_query_and_fragment;
mod error;
mod microledger;
mod microledger_node;
mod public_key_jwk;
mod public_key_params;
mod said_placeholder;
mod verification_method;

pub use crate::{
    did_document::DIDDocument,
    did_document_metadata::DIDDocumentMetadata,
    did_uri_components::DIDURIComponents,
    did_webplus::DIDWebplus,
    did_webplus_with_fragment::DIDWebplusWithFragment,
    did_webplus_with_query::DIDWebplusWithQuery,
    did_webplus_with_query_and_fragment::DIDWebplusWithQueryAndFragment,
    error::Error,
    microledger::Microledger,
    microledger_node::MicroledgerNode,
    public_key_jwk::PublicKeyJWK,
    public_key_params::{PublicKeyParams, PublicKeyParamsEC, PublicKeyParamsOKP},
    said_placeholder::{said_placeholder, said_placeholder_for_uri},
    verification_method::VerificationMethod,
};

pub const DID_DOCUMENT_HASH_FUNCTION_CODE: said::derivation::HashFunctionCode =
    said::derivation::HashFunctionCode::Blake3_256;
pub const SAID_HASH_FUNCTION_CODE: said::derivation::HashFunctionCode =
    said::derivation::HashFunctionCode::Blake3_256;
