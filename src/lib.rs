mod did;
mod did_document;
mod did_document_create_params;
mod did_document_metadata;
mod did_document_update_params;
mod did_fully_qualified;
mod did_fully_qualified_str;
mod did_resource;
mod did_resource_fully_qualified;
mod did_resource_fully_qualified_str;
mod did_resource_str;
mod did_str;
mod did_webplus_uri_components;
mod did_with_query;
mod did_with_query_str;
mod error;
mod key_purpose;
mod key_purpose_flags;
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
mod relative_resource;
mod relative_resource_str;
mod verification_method;

pub(crate) use crate::did_fully_qualified_str::parse_did_query_params;
pub use crate::{
    did::DID,
    did_document::DIDDocument,
    did_document_create_params::DIDDocumentCreateParams,
    did_document_metadata::{
        DIDDocumentMetadata, DIDDocumentMetadataConstant, DIDDocumentMetadataCurrency,
        DIDDocumentMetadataIdempotent, RequestedDIDDocumentMetadata,
    },
    did_document_update_params::DIDDocumentUpdateParams,
    did_fully_qualified::DIDFullyQualified,
    did_fully_qualified_str::DIDFullyQualifiedStr,
    did_resource::DIDResource,
    did_resource_fully_qualified::DIDResourceFullyQualified,
    did_resource_fully_qualified_str::DIDResourceFullyQualifiedStr,
    did_resource_str::DIDResourceStr,
    did_str::DIDStr,
    did_webplus_uri_components::DIDWebplusURIComponents,
    did_with_query::DIDWithQuery,
    did_with_query_str::DIDWithQueryStr,
    error::Error,
    key_purpose::KeyPurpose,
    key_purpose_flags::KeyPurposeFlags,
    microledger_mut_view::MicroledgerMutView,
    microledger_view::MicroledgerView,
    public_key_jwk::PublicKeyJWK,
    public_key_material::PublicKeyMaterial,
    public_key_params::PublicKeyParams,
    public_key_params_ec::PublicKeyParamsEC,
    public_key_params_okp::PublicKeyParamsOKP,
    public_key_set::PublicKeySet,
    relative_resource::{Fragment, RelativeResource},
    relative_resource_str::RelativeResourceStr,
    verification_method::VerificationMethod,
};
#[cfg(feature = "async-traits")]
pub use crate::{
    microledger_mut_view_async::MicroledgerMutViewAsync,
    microledger_view_async::MicroledgerViewAsync,
};

pub type RelativeKeyResource = RelativeResource<selfsign::KERIVerifierStr>;
pub type RelativeKeyResourceStr = RelativeResourceStr<selfsign::KERIVerifierStr>;
pub type DIDKeyResource = DIDResource<selfsign::KERIVerifierStr>;
pub type DIDKeyResourceFullyQualified = DIDResourceFullyQualified<selfsign::KERIVerifierStr>;
pub type DIDKeyResourceFullyQualifiedStr = DIDResourceFullyQualifiedStr<selfsign::KERIVerifierStr>;
