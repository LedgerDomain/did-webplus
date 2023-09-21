mod did_document;
mod did_document_create_params;
mod did_document_metadata;
mod did_document_update_params;
mod did_uri_components;
mod did_webplus;
mod did_webplus_fragment;
mod did_webplus_with_fragment;
mod did_webplus_with_query;
mod did_webplus_with_query_and_fragment;
mod error;
mod microledger;
mod non_root_did_document;
mod public_key_jwk;
mod public_key_material;
mod public_key_params;
mod public_key_params_ec;
mod public_key_params_okp;
mod public_key_set;
mod root_did_document;
mod verification_method;

pub use crate::{
    did_document::DIDDocument,
    did_document_create_params::DIDDocumentCreateParams,
    did_document_metadata::DIDDocumentMetadata,
    did_document_update_params::DIDDocumentUpdateParams,
    did_uri_components::DIDURIComponents,
    did_webplus::DIDWebplus,
    did_webplus_fragment::{DIDWebplusFragment, Fragment},
    did_webplus_with_fragment::DIDWebplusWithFragment,
    did_webplus_with_query::DIDWebplusWithQuery,
    did_webplus_with_query_and_fragment::DIDWebplusWithQueryAndFragment,
    error::Error,
    microledger::Microledger,
    non_root_did_document::NonRootDIDDocument,
    public_key_jwk::PublicKeyJWK,
    public_key_material::PublicKeyMaterial,
    public_key_params::PublicKeyParams,
    public_key_params_ec::PublicKeyParamsEC,
    public_key_params_okp::PublicKeyParamsOKP,
    public_key_set::PublicKeySet,
    root_did_document::RootDIDDocument,
    verification_method::VerificationMethod,
};

pub type DIDWebplusKeyIdFragment = DIDWebplusFragment<selfsign::KERIVerifier<'static>>;
pub type DIDWebplusWithKeyIdFragment = DIDWebplusWithFragment<selfsign::KERIVerifier<'static>>;
pub type DIDWebplusWithQueryAndKeyIdFragment =
    DIDWebplusWithQueryAndFragment<selfsign::KERIVerifier<'static>>;
