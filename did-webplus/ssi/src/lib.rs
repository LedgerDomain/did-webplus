mod jwt;
mod vc;
mod vp;

pub use crate::{
    jwt::{decode_jwt, sign_jwt, verify_jwt},
    vc::{issue_vc_jwt, issue_vc_ldp, new_unsigned_credential, verify_vc_jwt, verify_vc_ldp},
    vp::{
        issue_vp_jwt, issue_vp_ldp, new_unsigned_presentation, verify_vp_jwt, verify_vp_ldp,
        IssueVPParameters,
    },
};
pub use anyhow::{Error, Result};

use std::{str::FromStr, sync::Arc};

#[derive(Clone)]
pub struct DIDWebplus {
    pub did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
}

impl ssi_dids::DIDMethod for DIDWebplus {
    const DID_METHOD_NAME: &'static str = "webplus";
}

impl ssi_dids::DIDMethodResolver for DIDWebplus {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: ssi_dids::resolution::Options,
    ) -> std::result::Result<ssi_dids::resolution::Output<Vec<u8>>, ssi_dids::resolution::Error>
    {
        tracing::debug!(
            "DIDWebplus::resolve_method_representation; method_specific_id: {:?}, options: {:?}",
            method_specific_id,
            options
        );
        let self_hash_o =
            if let Some(ssi_dids::resolution::Parameter::String(self_hash_string)) =
                options.parameters.additional.get("selfHash")
            {
                Some(mbx::MBHashStr::new_ref(self_hash_string).map_err(|e| {
                    ssi_dids::resolution::Error::InvalidMethodSpecificId(e.to_string())
                })?)
            } else {
                None
            };
        let version_id_o = if let Some(version_id_str) = options.parameters.version_id.as_deref() {
            let version_id = u32::from_str(version_id_str)
                .map_err(|e| ssi_dids::resolution::Error::InvalidMethodSpecificId(e.to_string()))?;
            Some(version_id)
        } else {
            None
        };
        let did = did_webplus_core::DID::try_from(format!("did:webplus:{}", method_specific_id))
            .map_err(|e| ssi_dids::resolution::Error::InvalidMethodSpecificId(e.to_string()))?;
        tracing::debug!("DIDWebplus::resolve_method_representation; did: {}", did);
        let did_query = match (self_hash_o, version_id_o) {
            (Some(self_hash), Some(version_id)) => {
                did.with_queries(&self_hash, version_id).to_string()
            }
            (Some(self_hash), None) => did.with_query_self_hash(&self_hash).to_string(),
            (None, Some(version_id)) => did.with_query_version_id(version_id).to_string(),
            (None, None) => did.to_string(),
        };
        let (did_document_jcs, did_document_metadata, did_resolution_metadata) = self
            .did_resolver_a
            .resolve_did_document_string(
                did_query.as_str(),
                // TEMP HACK -- no metadata -- TODO Implement, also TODO: make local-only resolution specifiable.
                did_webplus_core::DIDResolutionOptions::no_metadata(false),
            )
            .await
            .map_err(|e| ssi_dids::resolution::Error::Internal(e.to_string()))?;
        tracing::debug!("DIDWebplus::resolve_method_representation; resolution successful; did_document_jcs: {}\n\tdid_document_metadata: {:?}\n\tdid_resolution_metadata: {:?}", did_document_jcs, did_document_metadata, did_resolution_metadata);
        Ok(ssi_dids::resolution::Output {
            document: did_document_jcs.as_bytes().to_vec(),
            document_metadata: Default::default(),
            metadata: ssi_dids::resolution::Metadata {
                content_type: Some(ssi_dids::document::representation::MediaType::Json.to_string()),
            },
        })
    }
}

// /// Picks the appropriate cryptographic suite for a did:webplus verification method.
// ///
// /// This is used when signing LDP-format VCs and VPs without a JWK, since
// /// `AnySuite::pick` requires a JWK to determine the algorithm.
// ///
// /// For did:webplus, the suite is always `JsonWebSignature2020`.
// pub(crate) fn pick_suite_for_did_webplus(
//     verification_method: &ssi_verification_methods::AnyMethod,
// ) -> Option<ssi_claims::data_integrity::AnySuite> {
//     use ssi_verification_methods::VerificationMethod;
//     pick_suite_for_did_webplus_by_id(verification_method.id().as_str())
// }

/// Picks the suite by verification method ID string (e.g. when you only have the key_id).
pub(crate) fn pick_suite_for_did_webplus_by_id(
    id: &str,
) -> Option<ssi_claims::data_integrity::AnySuite> {
    if id.starts_with("did:webplus:") {
        Some(ssi_claims::data_integrity::AnySuite::JsonWebSignature2020)
    } else {
        None
    }
}
