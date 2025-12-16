use crate::REQWEST_CLIENT;
use did_webplus_core::{
    DIDDocument, DIDFullyQualified, DIDStr, HTTPHeadersFor, KeyPurpose, KeyPurposeFlags,
    RootLevelUpdateRules, UpdateKey, UpdatesDisallowed, now_utc_milliseconds,
};
use did_webplus_wallet::{Error, Result, Wallet};
use did_webplus_wallet_store::{
    LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyRecordFilter, PrivKeyUsage,
    PrivKeyUsageRecord, VerificationMethodRecord, WalletStorage, WalletStorageCtx,
};
use signature_dyn::SignerDynT;
use std::{borrow::Cow, sync::Arc};

#[derive(Clone)]
pub struct SoftwareWallet {
    ctx: WalletStorageCtx,
    wallet_storage_a: Arc<dyn WalletStorage>,
    /// Optionally specifies the host (i.e. hostname and optional port number) of a VDG to use in the
    /// DIDResolverFull for fetching DID documents.  This is used so that this resolver can take part
    /// in the scope of agreement defined by the VDG.  Without using a VDG, a DIDResolverFull has a
    /// scope of agreement that only contains itself.
    vdg_host_o: Option<String>,
}

impl SoftwareWallet {
    pub async fn create(
        transaction: &mut dyn storage_traits::TransactionDynT,
        wallet_storage_a: Arc<dyn WalletStorage>,
        wallet_name_o: Option<String>,
        vdg_host_o: Option<String>,
    ) -> Result<Self> {
        // Validate vdg_host_o.
        if let Some(vdg_host) = vdg_host_o.as_deref() {
            let http_scheme =
                did_webplus_core::HTTPSchemeOverride::default_http_scheme_for_host(vdg_host)
                    .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
            let _vdg_base_url = url::Url::parse(&format!("{}://{}", http_scheme, vdg_host))
                .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
        }

        let wallet_storage_ctx = wallet_storage_a
            .create_wallet(Some(transaction), wallet_name_o)
            .await?;
        Ok(Self {
            ctx: wallet_storage_ctx,
            wallet_storage_a,
            vdg_host_o,
        })
    }
    pub async fn open(
        transaction: &mut dyn storage_traits::TransactionDynT,
        wallet_storage_a: Arc<dyn WalletStorage>,
        wallet_uuid: &uuid::Uuid,
        vdg_host_o: Option<String>,
    ) -> Result<Self> {
        // Validate vdg_host_o.
        if let Some(vdg_host) = vdg_host_o.as_deref() {
            let http_scheme =
                did_webplus_core::HTTPSchemeOverride::default_http_scheme_for_host(vdg_host)
                    .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
            let _vdg_base_url = url::Url::parse(&format!("{}://{}", http_scheme, vdg_host))
                .map_err(|e| Error::MalformedVDGHost(e.to_string().into()))?;
        }

        let (wallet_storage_ctx, _wallet_record) = wallet_storage_a
            .get_wallet(Some(transaction), wallet_uuid)
            .await?
            .ok_or_else(|| {
                Error::NotFound(format!("Wallet with wallet_uuid {}", wallet_uuid).into())
            })?;
        Ok(Self {
            ctx: wallet_storage_ctx,
            wallet_storage_a,
            vdg_host_o,
        })
    }
    async fn fetch_did_internal(
        &self,
        did: &DIDStr,
        http_headers_for_o: Option<&HTTPHeadersFor>,
        http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<did_webplus_core::DIDDocument> {
        // Note the version of the known latest DID document.  This will only differ from the actual latest
        // version if more than one wallet controls the DID.

        // Retrieve any unfetched updates to the DID.
        let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
            did_webplus_doc_store::DIDDocStore::new(
                self.wallet_storage_a.clone().as_did_doc_storage_a(),
            ),
            self.vdg_host_o.as_deref(),
            http_headers_for_o.cloned(),
            http_scheme_override_o.cloned(),
        )
        .unwrap();
        use did_webplus_resolver::DIDResolver;
        let (did_document, _did_document_metadata, _did_resolution_metadata) = did_resolver_full
            .resolve_did_document(
                did.as_str(),
                did_webplus_core::DIDResolutionOptions::no_metadata(false),
            )
            .await
            .map_err(|e| Error::DIDFetchError(format!("DID: {}, error was: {}", did, e).into()))?;

        Ok(did_document)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Wallet for SoftwareWallet {
    async fn create_did(
        &self,
        vdr_did_create_endpoint: &str,
        http_headers_for_o: Option<&did_webplus_core::HTTPHeadersFor>,
        http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<DIDFullyQualified> {
        tracing::debug!(
            ?vdr_did_create_endpoint,
            ?http_headers_for_o,
            ?http_scheme_override_o,
            "creating DID"
        );

        // Parse the vdr_did_create_endpoint as a URL.
        let vdr_did_create_endpoint_url =
            url::Url::parse(vdr_did_create_endpoint).map_err(|e| {
                Error::InvalidVDRDIDCreateURL(
                    format!(
                        "Parse error in VDR DID Create endpoint URL {:?} -- error was: {}",
                        vdr_did_create_endpoint, e
                    )
                    .into(),
                )
            })?;
        if vdr_did_create_endpoint_url.host_str().is_none() {
            return Err(Error::InvalidVDRDIDCreateURL(
                format!(
                    "VDR DID Create endpoint URL {:?} has no hostname",
                    vdr_did_create_endpoint
                )
                .into(),
            ));
        }
        let did_path_o = {
            let path = vdr_did_create_endpoint_url
                .path()
                .strip_prefix('/')
                .expect("programmer error");
            let path = if let Some(path) = path.strip_suffix('/') {
                path
            } else {
                path
            };
            if path.is_empty() {
                None
            } else if path.contains('/') {
                Some(Cow::Owned(path.replace("/", ":")))
            } else {
                Some(Cow::Borrowed(path))
            }
        };

        // Generate an appropriate set of keys.  Record the creation timestamp.
        let now_utc = now_utc_milliseconds();
        // TODO: Somehow iterate?
        let priv_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::AssertionMethod => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::KeyAgreement => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityInvocation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityDelegation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::UpdateDIDDocument => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        };
        // TODO: Somehow iterate?
        let pub_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::Authentication].verifying_key()),
            KeyPurpose::AssertionMethod => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::AssertionMethod].verifying_key()),
            KeyPurpose::KeyAgreement => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::KeyAgreement].verifying_key()),
            KeyPurpose::CapabilityInvocation => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::CapabilityInvocation].verifying_key()),
            KeyPurpose::CapabilityDelegation => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::CapabilityDelegation].verifying_key()),
            KeyPurpose::UpdateDIDDocument => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::UpdateDIDDocument].verifying_key()),
        };

        // Define the update rules.  For now, just a single key.
        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: pub_key_m[KeyPurpose::UpdateDIDDocument].clone(),
        });

        // Form the unsigned root DID document.
        let mut did_document = DIDDocument::create_unsigned_root(
            vdr_did_create_endpoint_url.host_str().unwrap(),
            vdr_did_create_endpoint_url.port(),
            did_path_o.as_deref(),
            update_rules,
            now_utc,
            did_webplus_core::PublicKeySet {
                authentication_v: vec![&pub_key_m[KeyPurpose::Authentication]],
                assertion_method_v: vec![&pub_key_m[KeyPurpose::AssertionMethod]],
                key_agreement_v: vec![&pub_key_m[KeyPurpose::KeyAgreement]],
                capability_invocation_v: vec![&pub_key_m[KeyPurpose::CapabilityInvocation]],
                capability_delegation_v: vec![&pub_key_m[KeyPurpose::CapabilityDelegation]],
            },
            &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
        )
        .expect("programmer error");

        // There's no need to sign the root DID document, but it is allowed.  There could be
        // reasons outside of the did:webplus specification for doing so.

        // Finalize the root DID document.
        did_document.finalize(None).expect("programmer error");

        // Sanity check.
        did_document
            .verify_root_nonrecursive()
            .expect("programmer error");

        // Now that the DID document is finalized, we can get the DID.
        let did = did_document.did.as_did_str();

        tracing::trace!(?did, "created root DID document");

        let mut transaction_b = self
            .wallet_storage_a
            .begin_transaction()
            .await
            .map_err(|e| Error::WalletStorageError(e.into()))?;

        // Serialize DID doc as JCS (JSON Canonicalization Scheme), then
        // POST the DID document to the VDR to create the DID.
        {
            let did_document_jcs = did_document
                .serialize_canonically()
                .expect("this shouldn't happen");
            tracing::trace!("serialized root DID document: {}", did_document_jcs);

            // Another sanity check.
            let parsed_did_document = serde_json::from_str::<DIDDocument>(&did_document_jcs)
                .expect("this shouldn't happen");
            assert_eq!(parsed_did_document, did_document);
            parsed_did_document
                .verify_root_nonrecursive()
                .expect("programmer error");

            // Store the DID doc.  Note that this will also ingest the verification methods from the DID doc,
            // which represents the control of the versioned DID.
            self.wallet_storage_a
                .add_did_document(
                    Some(transaction_b.as_mut()),
                    &did_document,
                    did_document_jcs.as_str(),
                )
                .await?;

            let header_map = {
                let mut header_map = reqwest::header::HeaderMap::new();
                if let Some(http_headers_for) = http_headers_for_o {
                    if let Some(http_header_v) =
                        http_headers_for.http_headers_for_hostname(did.hostname())
                    {
                        for http_header in http_header_v {
                            header_map.insert(
                                reqwest::header::HeaderName::from_bytes(http_header.name.as_bytes()).map_err(|e| Error::Malformed(format!("Failed to parse HTTP header name from {:?}; error was: {}", http_header.name, e).into()))?,
                                reqwest::header::HeaderValue::from_str(&http_header.value).map_err(|e| Error::Malformed(format!("Failed to parse HTTP header {:?} value to HeaderValue; error was: {}", http_header, e).into()))?,
                            );
                        }
                    }
                }
                header_map
            };

            // HTTP POST is for DID create operation.
            tracing::trace!("HTTP POST-ing DID document to VDR: {}", did_document_jcs);
            REQWEST_CLIENT
                .clone()
                .post(did.resolution_url_for_did_documents_jsonl(http_scheme_override_o))
                .headers(header_map)
                .body(did_document_jcs)
                .send()
                .await
                .map_err(|e| Error::HTTPRequestError(e.to_string().into()))?
                .error_for_status()
                .map_err(|e| Error::HTTPOperationStatus(e.to_string().into()))?;
        }

        // Store the priv keys
        for key_purpose in KeyPurpose::VARIANTS {
            let pub_key = pub_key_m[key_purpose].clone();
            let hashed_pub_key = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(pub_key.as_bytes());
                mbx::MBHash::from_blake3(mbx::Base::Base64Url, hasher)
            };
            let max_usage_count_o = if key_purpose == KeyPurpose::UpdateDIDDocument {
                Some(1)
            } else {
                None
            };
            let comment_o = Some("generated during DID create".to_string());
            use signature_dyn::SignerDynT;
            self.wallet_storage_a
                .add_priv_key(
                    Some(transaction_b.as_mut()),
                    &self.ctx,
                    PrivKeyRecord {
                        pub_key,
                        hashed_pub_key: hashed_pub_key.to_string(),
                        did_restriction_o: Some(did.to_string()),
                        key_purpose_restriction_o: Some(KeyPurposeFlags::from(key_purpose)),
                        created_at: now_utc,
                        last_used_at_o: None,
                        max_usage_count_o,
                        usage_count: 0,
                        deleted_at_o: None,
                        private_key_bytes_o: Some(
                            priv_key_m[key_purpose].to_signer_bytes().to_owned(),
                        ),
                        comment_o,
                    },
                )
                .await?;
        }

        // Derive the controlled DID.
        let controlled_did = did.with_queries(&did_document.self_hash, 0);

        transaction_b
            .commit()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;

        Ok(controlled_did)
    }
    // TODO: Figure out how to update any other local doc stores.
    async fn fetch_did(
        &self,
        did: &DIDStr,
        http_headers_for_o: Option<&did_webplus_core::HTTPHeadersFor>,
        http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<()> {
        tracing::debug!(
            ?did,
            ?http_headers_for_o,
            ?http_scheme_override_o,
            "fetching DID"
        );
        self.fetch_did_internal(did, http_headers_for_o, http_scheme_override_o)
            .await?;
        Ok(())
    }
    async fn update_did(
        &self,
        did: &DIDStr,
        http_headers_for_o: Option<&did_webplus_core::HTTPHeadersFor>,
        http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<DIDFullyQualified> {
        tracing::debug!(
            ?did,
            ?http_headers_for_o,
            ?http_scheme_override_o,
            "updating DID"
        );

        // Fetch external updates to the DID before updating it.  This is only relevant if more than one wallet
        // controls the DID.
        let latest_did_document = self
            .fetch_did_internal(did, http_headers_for_o, http_scheme_override_o)
            .await?;

        // Rotate the appropriate set of keys.  Record the creation timestamp.
        let now_utc = now_utc_milliseconds();
        // TODO: Somehow iterate?
        let priv_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::AssertionMethod => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::KeyAgreement => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityInvocation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityDelegation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::UpdateDIDDocument => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        };
        // TODO: Somehow iterate?
        let pub_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::Authentication].verifying_key()),
            KeyPurpose::AssertionMethod => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::AssertionMethod].verifying_key()),
            KeyPurpose::KeyAgreement => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::KeyAgreement].verifying_key()),
            KeyPurpose::CapabilityInvocation => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::CapabilityInvocation].verifying_key()),
            KeyPurpose::CapabilityDelegation => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::CapabilityDelegation].verifying_key()),
            KeyPurpose::UpdateDIDDocument => mbx::MBPubKey::from_ed25519_dalek_verifying_key(mbx::Base::Base64Url, &priv_key_m[KeyPurpose::UpdateDIDDocument].verifying_key()),
        };

        let mut transaction_b = self
            .wallet_storage_a
            .begin_transaction()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;

        // Select all the locally-controlled verification methods that are in the latest DID document, so
        // that the keys can be retired, and new keys generated, put in the DID update, and then stored
        // in the wallet.
        let locally_controlled_verification_method_v = self
            .wallet_storage_a
            .get_locally_controlled_verification_methods(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &LocallyControlledVerificationMethodFilter {
                    did_o: Some(did.to_owned()),
                    version_id_o: Some(latest_did_document.version_id),
                    key_purpose_o: None,
                    key_id_o: None,
                    result_limit_o: None,
                },
            )
            .await?;
        let update_key_v = self
            .wallet_storage_a
            .get_priv_keys(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &PrivKeyRecordFilter {
                    pub_key_o: None,
                    hashed_pub_key_o: None,
                    did_o: Some(did.to_string()),
                    key_purpose_flags_o: Some(KeyPurposeFlags::from(KeyPurpose::UpdateDIDDocument)),
                    is_not_deleted_o: Some(true),
                },
            )
            .await?;
        tracing::trace!(
            "found {} update keys for {}: {:?}",
            update_key_v.len(),
            did,
            update_key_v
                .iter()
                .map(|priv_key_record| &priv_key_record.pub_key)
                .collect::<Vec<_>>()
        );

        // If there are no matching update keys, then this means that this wallet doesn't have
        // the authority to update the DID.  This could happen if another wallet updated the DID
        // and removed this wallet's update key.
        if update_key_v.is_empty() {
            return Err(Error::NoSuitablePrivKeyFound(format!("this wallet has no update key for {}, so DID cannot be updated by this wallet; latest DID doc has selfHash {} and versionId {}", did, latest_did_document.self_hash, latest_did_document.version_id).into()));
        }

        // TEMP HACK: Assume there will only be one update key per wallet.
        assert_eq!(
            update_key_v.len(),
            1,
            "programmer error: assumption is that there should only be one update key per wallet"
        );

        // Select the appropriate key to sign the update.
        let priv_key_record_for_update = &update_key_v[0];
        let priv_key_for_update = priv_key_record_for_update
            .private_key_bytes_o
            .as_ref()
            .expect(
                "programmer error: priv_key_bytes_o was expected to be Some(_); i.e. not deleted",
            );

        // Define the update rules.  For now, just a single key.
        let update_rules = RootLevelUpdateRules::from(UpdateKey {
            pub_key: pub_key_m[KeyPurpose::UpdateDIDDocument].clone(),
        });

        // Form the unsigned non-root DID document.
        let mut updated_did_document = DIDDocument::create_unsigned_non_root(
            &latest_did_document,
            update_rules,
            now_utc,
            did_webplus_core::PublicKeySet {
                authentication_v: vec![&pub_key_m[KeyPurpose::Authentication]],
                assertion_method_v: vec![&pub_key_m[KeyPurpose::AssertionMethod]],
                key_agreement_v: vec![&pub_key_m[KeyPurpose::KeyAgreement]],
                capability_invocation_v: vec![&pub_key_m[KeyPurpose::CapabilityInvocation]],
                capability_delegation_v: vec![&pub_key_m[KeyPurpose::CapabilityDelegation]],
            },
            &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
        )
        .expect("programmer error");

        let signing_kid = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &priv_key_for_update.verifier_bytes()?,
        )
        .expect("programmer error")
        .to_string();

        // The updated DID document must be signed by the UpdateDIDDocument key specified in the latest DID document.
        let jws = updated_did_document
            .sign(signing_kid, priv_key_for_update)
            .expect("programmer error");

        // Add the proof to the DID document.
        updated_did_document.add_proof(jws.into_string());

        // Finalize the DID document.
        updated_did_document
            .finalize(Some(&latest_did_document))
            .expect("programmer error");

        // Sanity check.
        updated_did_document
            .verify_non_root_nonrecursive(&latest_did_document)
            .expect("programmer error");

        // Serialize DID doc as JCS (JSON Canonicalization Scheme), then
        // PUT the DID document to the VDR to update the DID.
        {
            let updated_did_document_jcs = updated_did_document
                .serialize_canonically()
                .expect("this shouldn't happen");
            tracing::debug!("updated_did_document_jcs: {}", updated_did_document_jcs);
            // Store the DID doc.  Note that this will also ingest the verification methods from the DID doc,
            // which represents the control of the versioned DID.
            self.wallet_storage_a
                .add_did_document(
                    Some(transaction_b.as_mut()),
                    &updated_did_document,
                    updated_did_document_jcs.as_str(),
                )
                .await?;

            let header_map = {
                let mut header_map = reqwest::header::HeaderMap::new();
                if let Some(http_headers_for) = http_headers_for_o {
                    if let Some(http_header_v) =
                        http_headers_for.http_headers_for_hostname(did.hostname())
                    {
                        for http_header in http_header_v {
                            header_map.insert(
                                reqwest::header::HeaderName::from_bytes(http_header.name.as_bytes()).map_err(|e| Error::Malformed(format!("Failed to parse HTTP header name from {:?}; error was: {}", http_header.name, e).into()))?,
                                reqwest::header::HeaderValue::from_str(&http_header.value).map_err(|e| Error::Malformed(format!("Failed to parse HTTP header {:?} value to HeaderValue; error was: {}", http_header, e).into()))?,
                            );
                        }
                    }
                }
                header_map
            };

            // HTTP PUT is for DID update operation.
            tracing::trace!(
                "HTTP PUT-ing DID document to VDR: {}",
                updated_did_document_jcs
            );
            REQWEST_CLIENT
                .clone()
                .put(did.resolution_url_for_did_documents_jsonl(http_scheme_override_o))
                .headers(header_map)
                .body(updated_did_document_jcs)
                .send()
                .await
                .map_err(|e| Error::HTTPRequestError(e.to_string().into()))?
                .error_for_status()
                .map_err(|e| Error::HTTPOperationStatus(e.to_string().into()))?;
        }

        // Store the priv keys
        for key_purpose in KeyPurpose::VARIANTS {
            let pub_key = pub_key_m[key_purpose].clone();
            let hashed_pub_key = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(pub_key.as_bytes());
                mbx::MBHash::from_blake3(mbx::Base::Base64Url, hasher)
            };
            let max_usage_count_o = if key_purpose == KeyPurpose::UpdateDIDDocument {
                Some(1)
            } else {
                None
            };
            let comment_o = Some(format!(
                "generated during DID update versionId {} -> {}",
                latest_did_document.version_id, updated_did_document.version_id
            ));
            self.wallet_storage_a
                .add_priv_key(
                    Some(transaction_b.as_mut()),
                    &self.ctx,
                    PrivKeyRecord {
                        pub_key,
                        hashed_pub_key: hashed_pub_key.to_string(),
                        did_restriction_o: Some(did.to_string()),
                        key_purpose_restriction_o: Some(KeyPurposeFlags::from(key_purpose)),
                        created_at: now_utc,
                        last_used_at_o: None,
                        max_usage_count_o,
                        usage_count: 0,
                        deleted_at_o: None,
                        private_key_bytes_o: Some(
                            priv_key_m[key_purpose].to_signer_bytes().into_owned(),
                        ),
                        comment_o,
                    },
                )
                .await?;
        }

        let controlled_did = did.with_queries(
            &updated_did_document.self_hash,
            updated_did_document.version_id,
        );

        // Add the UpdateDIDDocument priv key usage.
        self.wallet_storage_a
            .add_priv_key_usage(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &PrivKeyUsageRecord {
                    pub_key: priv_key_record_for_update.pub_key.clone(),
                    hashed_pub_key: priv_key_record_for_update.hashed_pub_key.clone(),
                    used_at: now_utc,
                    usage: PrivKeyUsage::DIDUpdate {
                        updated_did_fully_qualified_o: Some(controlled_did.clone()),
                    },
                    verification_method_o: None,
                    key_purpose_o: Some(KeyPurpose::UpdateDIDDocument),
                },
            )
            .await?;

        // Retire the priv keys for the old locally-controlled verification methods.
        for (_verification_method_record, priv_key_record) in
            locally_controlled_verification_method_v.into_iter()
        {
            self.wallet_storage_a
                .delete_priv_key(
                    Some(transaction_b.as_mut()),
                    &self.ctx,
                    &priv_key_record.pub_key,
                )
                .await?;
        }
        // Retire the old update key.
        self.wallet_storage_a
            .delete_priv_key(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &priv_key_record_for_update.pub_key,
            )
            .await?;

        transaction_b
            .commit()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;

        Ok(controlled_did)
    }
    async fn deactivate_did(
        &self,
        did: &DIDStr,
        http_headers_for_o: Option<&did_webplus_core::HTTPHeadersFor>,
        http_scheme_override_o: Option<&did_webplus_core::HTTPSchemeOverride>,
    ) -> Result<DIDFullyQualified> {
        tracing::debug!(
            ?did,
            ?http_headers_for_o,
            ?http_scheme_override_o,
            "deactivating DID"
        );
        // TODO: Factor this with update_did and create_did.

        // Fetch external updates to the DID before updating it.  This is only relevant if more than one wallet
        // controls the DID.
        let latest_did_document = self
            .fetch_did_internal(did, http_headers_for_o, http_scheme_override_o)
            .await?;

        // Record the DID update timestamp.
        let now_utc = now_utc_milliseconds();

        let mut transaction_b = self
            .wallet_storage_a
            .begin_transaction()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;

        // Select all the locally-controlled verification methods that are in the latest DID document, so
        // that the keys can be retired, and new keys generated, put in the DID update, and then stored
        // in the wallet.
        let locally_controlled_verification_method_v = self
            .wallet_storage_a
            .get_locally_controlled_verification_methods(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &LocallyControlledVerificationMethodFilter {
                    did_o: Some(did.to_owned()),
                    version_id_o: Some(latest_did_document.version_id),
                    key_purpose_o: None,
                    key_id_o: None,
                    result_limit_o: None,
                },
            )
            .await?;
        let update_key_v = self
            .wallet_storage_a
            .get_priv_keys(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &PrivKeyRecordFilter {
                    pub_key_o: None,
                    hashed_pub_key_o: None,
                    did_o: Some(did.to_string()),
                    key_purpose_flags_o: Some(KeyPurposeFlags::from(KeyPurpose::UpdateDIDDocument)),
                    is_not_deleted_o: Some(true),
                },
            )
            .await?;
        tracing::trace!(
            "found {} update keys for {}: {:?}",
            update_key_v.len(),
            did,
            update_key_v
                .iter()
                .map(|priv_key_record| &priv_key_record.pub_key)
                .collect::<Vec<_>>()
        );

        // If there are no matching update keys, then this means that this wallet doesn't have
        // the authority to update the DID.  This could happen if another wallet updated the DID
        // and removed this wallet's update key.
        if update_key_v.is_empty() {
            return Err(Error::NoSuitablePrivKeyFound(format!("this wallet has no update key for {}, so DID cannot be updated by this wallet; latest DID doc has selfHash {} and versionId {}", did, latest_did_document.self_hash, latest_did_document.version_id).into()));
        }

        // TEMP HACK: Assume there will only be one update key per wallet.
        assert_eq!(
            update_key_v.len(),
            1,
            "programmer error: assumption is that there should only be one update key per wallet"
        );

        // Select the appropriate key to sign the update.
        let priv_key_record_for_update = &update_key_v[0];
        let priv_key_for_update = priv_key_record_for_update
            .private_key_bytes_o
            .as_ref()
            .expect(
                "programmer error: priv_key_bytes_o was expected to be Some(_); i.e. not deleted",
            );

        // Define the update rules -- UpdatesDisallowed, thereby deactivating the DID.
        let update_rules = RootLevelUpdateRules::from(UpdatesDisallowed {});

        // Form the unsigned non-root DID document.
        let mut deactivated_did_document = DIDDocument::create_unsigned_non_root(
            &latest_did_document,
            update_rules,
            now_utc,
            did_webplus_core::PublicKeySet {
                authentication_v: vec![],
                assertion_method_v: vec![],
                key_agreement_v: vec![],
                capability_invocation_v: vec![],
                capability_delegation_v: vec![],
            },
            &selfhash::MBHashFunction::blake3(mbx::Base::Base64Url),
        )
        .expect("programmer error");

        let signing_kid = mbx::MBPubKey::try_from_verifier_bytes(
            mbx::Base::Base64Url,
            &priv_key_for_update.verifier_bytes()?,
        )
        .expect("programmer error")
        .to_string();

        // The updated DID document must be signed by the UpdateDIDDocument key specified in the latest DID document.
        let jws = deactivated_did_document
            .sign(signing_kid, priv_key_for_update)
            .expect("programmer error");

        // Add the proof to the DID document.
        deactivated_did_document.add_proof(jws.into_string());

        // Finalize the DID document.
        deactivated_did_document
            .finalize(Some(&latest_did_document))
            .expect("programmer error");

        // Sanity check.
        deactivated_did_document
            .verify_non_root_nonrecursive(&latest_did_document)
            .expect("programmer error");

        // Serialize DID doc as JCS (JSON Canonicalization Scheme), then
        // PUT the DID document to the VDR to update the DID.
        {
            let deactivated_did_document_jcs = deactivated_did_document
                .serialize_canonically()
                .expect("this shouldn't happen");
            tracing::debug!(
                "deactivated_did_document_jcs: {}",
                deactivated_did_document_jcs
            );
            // Store the DID doc.  Note that this will also ingest the verification methods from the DID doc,
            // which represents the control of the versioned DID.
            self.wallet_storage_a
                .add_did_document(
                    Some(transaction_b.as_mut()),
                    &deactivated_did_document,
                    deactivated_did_document_jcs.as_str(),
                )
                .await?;

            // Form the HTTP headers.
            let header_map = {
                let mut header_map = reqwest::header::HeaderMap::new();
                if let Some(http_headers_for) = http_headers_for_o {
                    if let Some(http_header_v) =
                        http_headers_for.http_headers_for_hostname(did.hostname())
                    {
                        for http_header in http_header_v {
                            header_map.insert(
                                reqwest::header::HeaderName::from_bytes(http_header.name.as_bytes()).map_err(|e| Error::Malformed(format!("Failed to parse HTTP header name from {:?}; error was: {}", http_header.name, e).into()))?,
                                reqwest::header::HeaderValue::from_str(&http_header.value).map_err(|e| Error::Malformed(format!("Failed to parse HTTP header {:?} value to HeaderValue; error was: {}", http_header, e).into()))?,
                        );
                        }
                    }
                }
                header_map
            };

            // HTTP PUT is for DID update operation (which includes deactivation).
            tracing::trace!(
                "HTTP PUT-ing DID document to VDR: {}",
                deactivated_did_document_jcs
            );
            REQWEST_CLIENT
                .clone()
                .put(did.resolution_url_for_did_documents_jsonl(http_scheme_override_o))
                .headers(header_map)
                .body(deactivated_did_document_jcs)
                .send()
                .await
                .map_err(|e| Error::HTTPRequestError(e.to_string().into()))?
                .error_for_status()
                .map_err(|e| Error::HTTPOperationStatus(e.to_string().into()))?;
        }

        let controlled_did = did.with_queries(
            &deactivated_did_document.self_hash,
            deactivated_did_document.version_id,
        );

        // Add the UpdateDIDDocument priv key usage.
        self.wallet_storage_a
            .add_priv_key_usage(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &PrivKeyUsageRecord {
                    pub_key: priv_key_record_for_update.pub_key.clone(),
                    hashed_pub_key: priv_key_record_for_update.hashed_pub_key.clone(),
                    used_at: now_utc,
                    usage: PrivKeyUsage::DIDUpdate {
                        updated_did_fully_qualified_o: Some(controlled_did.clone()),
                    },
                    verification_method_o: None,
                    key_purpose_o: Some(KeyPurpose::UpdateDIDDocument),
                },
            )
            .await?;

        // Retire the priv keys for the old locally-controlled verification methods.
        for (_verification_method_record, priv_key_record) in
            locally_controlled_verification_method_v.into_iter()
        {
            self.wallet_storage_a
                .delete_priv_key(
                    Some(transaction_b.as_mut()),
                    &self.ctx,
                    &priv_key_record.pub_key,
                )
                .await?;
        }
        // Retire the old update key.
        self.wallet_storage_a
            .delete_priv_key(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &priv_key_record_for_update.pub_key,
            )
            .await?;

        transaction_b
            .commit()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;

        Ok(controlled_did)
    }
    async fn get_locally_controlled_verification_methods(
        &self,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<
        Vec<(
            VerificationMethodRecord,
            signature_dyn::SignerBytes<'static>,
        )>,
    > {
        let mut transaction_b = self
            .wallet_storage_a
            .begin_transaction()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;
        let query_result_v = self
            .wallet_storage_a
            .get_locally_controlled_verification_methods(
                Some(transaction_b.as_mut()),
                &self.ctx,
                locally_controlled_verification_method_filter,
            )
            .await?;
        transaction_b
            .commit()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;
        Ok(query_result_v
            .into_iter()
            .map(|(verification_method_record, priv_key_record)| {
                let signer_bytes = priv_key_record.private_key_bytes_o.unwrap();
                (verification_method_record, signer_bytes)
            })
            .collect())
    }
}
