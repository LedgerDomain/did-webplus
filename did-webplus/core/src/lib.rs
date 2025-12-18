mod creation_metadata;
mod did;
mod did_document;
mod did_document_metadata;
mod did_fully_qualified;
mod did_fully_qualified_str;
mod did_resolution_metadata;
mod did_resolution_options;
mod did_resource;
mod did_resource_fully_qualified;
mod did_resource_fully_qualified_str;
mod did_resource_str;
mod did_str;
mod did_uri_components;
mod did_with_query;
mod did_with_query_str;
mod error;
mod http_headers_for;
mod http_options;
mod http_scheme_override;
mod key_purpose;
mod key_purpose_flags;
mod latest_update_metadata;
mod next_update_metadata;
mod public_key_jwk;
mod public_key_material;
mod public_key_params;
mod public_key_params_ec;
mod public_key_params_okp;
mod public_key_set;
mod relative_resource;
mod relative_resource_str;
mod update_rules;
mod verification_method;

pub(crate) use crate::did_fully_qualified_str::parse_did_query_params;
pub use crate::{
    creation_metadata::CreationMetadata,
    did::DID,
    did_document::DIDDocument,
    did_document_metadata::DIDDocumentMetadata,
    did_fully_qualified::DIDFullyQualified,
    did_fully_qualified_str::DIDFullyQualifiedStr,
    did_resolution_metadata::DIDResolutionMetadata,
    did_resolution_options::DIDResolutionOptions,
    did_resource::DIDResource,
    did_resource_fully_qualified::DIDResourceFullyQualified,
    did_resource_fully_qualified_str::DIDResourceFullyQualifiedStr,
    did_resource_str::DIDResourceStr,
    did_str::DIDStr,
    did_uri_components::DIDURIComponents,
    did_with_query::DIDWithQuery,
    did_with_query_str::DIDWithQueryStr,
    error::Error,
    http_headers_for::{HTTPHeader, HTTPHeadersFor},
    http_options::HTTPOptions,
    http_scheme_override::HTTPSchemeOverride,
    key_purpose::KeyPurpose,
    key_purpose_flags::KeyPurposeFlags,
    latest_update_metadata::LatestUpdateMetadata,
    next_update_metadata::NextUpdateMetadata,
    public_key_jwk::PublicKeyJWK,
    public_key_material::PublicKeyMaterial,
    public_key_params::PublicKeyParams,
    public_key_params_ec::PublicKeyParamsEC,
    public_key_params_okp::PublicKeyParamsOKP,
    public_key_set::PublicKeySet,
    relative_resource::{Fragment, RelativeResource},
    relative_resource_str::RelativeResourceStr,
    update_rules::{
        All, Any, HashedUpdateKey, RootLevelUpdateRules, Threshold, UpdateKey, UpdateRules,
        UpdatesDisallowed, ValidProofData, VerifyRulesT, WeightedUpdateRules,
    },
    verification_method::VerificationMethod,
};

pub type Result<T> = std::result::Result<T, Error>;

pub type RelativeKeyResource = RelativeResource<str>;
pub type RelativeKeyResourceStr = RelativeResourceStr<str>;
pub type DIDKeyResource = DIDResource<str>;
pub type DIDKeyResourceFullyQualified = DIDResourceFullyQualified<str>;
pub type DIDKeyResourceFullyQualifiedStr = DIDResourceFullyQualifiedStr<str>;

/// This function returns the current time in UTC with millisecond precision.  This precision
/// limit is required for interoperability with javascript systems (see
/// <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now>).
pub fn now_utc_milliseconds() -> time::OffsetDateTime {
    truncated_to_milliseconds(time::OffsetDateTime::now_utc())
}

pub fn is_truncated_to_milliseconds(t: time::OffsetDateTime) -> bool {
    t.nanosecond() % 1_000_000 == 0
}

pub fn truncated_to_milliseconds(t: time::OffsetDateTime) -> time::OffsetDateTime {
    let milliseconds = t.millisecond();
    let t = t.replace_millisecond(milliseconds).unwrap();
    assert!(is_truncated_to_milliseconds(t));
    t
}

pub fn is_truncated_to_seconds(t: time::OffsetDateTime) -> bool {
    t.nanosecond() == 0
}

pub fn truncated_to_seconds(t: time::OffsetDateTime) -> time::OffsetDateTime {
    let t = t.replace_millisecond(0).unwrap();
    assert!(is_truncated_to_seconds(t));
    t
}
