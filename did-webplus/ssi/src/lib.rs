mod jwk;
mod jwt;

pub use crate::{
    jwk::get_signing_jwk,
    jwt::{decode_jwt, sign_jwt, verify_jwt},
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
