mod did;
mod did_document;
mod did_document_create_params;
mod did_document_metadata;
mod did_document_update_params;
mod did_fragment;
mod did_uri_components;
mod did_with_fragment;
mod did_with_query;
mod did_with_query_and_fragment;
mod error;
mod key_purpose;
mod microledger_mut_view;
#[cfg(feature = "async-traits")]
mod microledger_mut_view_async;
mod microledger_view;
#[cfg(feature = "async-traits")]
mod microledger_view_async;
mod public_key_jwk;
mod public_key_material;
mod public_key_params;
mod public_key_params_ec;
mod public_key_params_okp;
mod public_key_set;
mod verification_method;

#[allow(deprecated)]
pub use crate::{
    did::DIDWebplus, did_fragment::DIDWebplusFragment, did_with_fragment::DIDWebplusWithFragment,
    did_with_query::DIDWebplusWithQuery,
    did_with_query_and_fragment::DIDWebplusWithQueryAndFragment,
};
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
    did_uri_components::DIDURIComponents,
    did_with_fragment::DIDWithFragment,
    did_with_query::DIDWithQuery,
    did_with_query_and_fragment::DIDWithQueryAndFragment,
    error::Error,
    key_purpose::KeyPurpose,
    microledger_mut_view::MicroledgerMutView,
    microledger_view::MicroledgerView,
    public_key_jwk::PublicKeyJWK,
    public_key_material::PublicKeyMaterial,
    public_key_params::PublicKeyParams,
    public_key_params_ec::PublicKeyParamsEC,
    public_key_params_okp::PublicKeyParamsOKP,
    public_key_set::PublicKeySet,
    verification_method::VerificationMethod,
};
#[cfg(feature = "async-traits")]
pub use crate::{
    microledger_mut_view_async::MicroledgerMutViewAsync,
    microledger_view_async::MicroledgerViewAsync,
};

#[allow(deprecated)]
#[deprecated = "Use DIDKeyIdFragment instead"]
pub type DIDWebplusKeyIdFragment = DIDFragment<selfsign::KERIVerifier<'static>>;
#[allow(deprecated)]
#[deprecated = "Use DIDWithKeyIdFragment instead"]
pub type DIDWebplusWithKeyIdFragment = DIDWithFragment<selfsign::KERIVerifier<'static>>;
#[allow(deprecated)]
#[deprecated = "Use DIDWithQueryAndKeyIdFragment instead"]
pub type DIDWebplusWithQueryAndKeyIdFragment =
    DIDWithQueryAndFragment<selfsign::KERIVerifier<'static>>;

pub type DIDKeyIdFragment = DIDFragment<selfsign::KERIVerifier<'static>>;
pub type DIDWithKeyIdFragment = DIDWithFragment<selfsign::KERIVerifier<'static>>;
pub type DIDWithQueryAndKeyIdFragment = DIDWithQueryAndFragment<selfsign::KERIVerifier<'static>>;
