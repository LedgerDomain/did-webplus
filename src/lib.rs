mod did;
mod did_document;
mod did_document_create_params;
mod did_document_metadata;
mod did_document_update_params;
mod did_fragment;
mod did_str;
mod did_uri_components;
mod error;
mod key_purpose;
mod key_purpose_flags;
mod microledger_mut_view;
#[cfg(feature = "async-traits")]
mod microledger_mut_view_async;
mod microledger_view;
#[cfg(feature = "async-traits")]
mod microledger_view_async;
mod parsed_did;
mod parsed_did_with_fragment;
mod parsed_did_with_query;
mod parsed_did_with_query_and_fragment;
mod public_key_jwk;
mod public_key_material;
mod public_key_params;
mod public_key_params_ec;
mod public_key_params_okp;
mod public_key_set;
mod verification_method;

pub use crate::{
    did::DID,
    did_document::DIDDocument,
    did_document_create_params::DIDDocumentCreateParams,
    did_document_metadata::{
        DIDDocumentMetadata, DIDDocumentMetadataConstant, DIDDocumentMetadataCurrency,
        DIDDocumentMetadataIdempotent, RequestedDIDDocumentMetadata,
    },
    did_document_update_params::DIDDocumentUpdateParams,
    did_fragment::{DIDFragment, Fragment},
    did_str::DIDStr,
    did_uri_components::DIDURIComponents,
    error::Error,
    key_purpose::KeyPurpose,
    key_purpose_flags::KeyPurposeFlags,
    microledger_mut_view::MicroledgerMutView,
    microledger_view::MicroledgerView,
    parsed_did::ParsedDID,
    parsed_did_with_fragment::ParsedDIDWithFragment,
    parsed_did_with_query::ParsedDIDWithQuery,
    parsed_did_with_query_and_fragment::ParsedDIDWithQueryAndFragment,
    public_key_jwk::PublicKeyJWK,
    public_key_material::PublicKeyMaterial,
    public_key_params::PublicKeyParams,
    public_key_params_ec::PublicKeyParamsEC,
    public_key_params_okp::PublicKeyParamsOKP,
    public_key_set::PublicKeySet,
    verification_method::VerificationMethod,
};
#[allow(deprecated)]
pub use crate::{
    did_fragment::DIDWebplusFragment, parsed_did::DIDWebplus,
    parsed_did_with_fragment::DIDWebplusWithFragment, parsed_did_with_query::DIDWebplusWithQuery,
    parsed_did_with_query_and_fragment::DIDWebplusWithQueryAndFragment,
};
#[cfg(feature = "async-traits")]
pub use crate::{
    microledger_mut_view_async::MicroledgerMutViewAsync,
    microledger_view_async::MicroledgerViewAsync,
};

#[allow(deprecated)]
#[deprecated = "Use DIDKeyIdFragment instead"]
pub type DIDWebplusKeyIdFragment = DIDFragment<selfsign::KERIVerifier>;
#[allow(deprecated)]
#[deprecated = "Use DIDWithKeyIdFragment instead"]
pub type DIDWebplusWithKeyIdFragment = ParsedDIDWithFragment<selfsign::KERIVerifier>;
#[allow(deprecated)]
#[deprecated = "Use DIDWithQueryAndKeyIdFragment instead"]
pub type DIDWebplusWithQueryAndKeyIdFragment =
    ParsedDIDWithQueryAndFragment<selfsign::KERIVerifier>;

pub type DIDKeyIdFragment = DIDFragment<selfsign::KERIVerifier>;
pub type DIDWithKeyIdFragment = ParsedDIDWithFragment<selfsign::KERIVerifier>;
pub type DIDWithQueryAndKeyIdFragment = ParsedDIDWithQueryAndFragment<selfsign::KERIVerifier>;
