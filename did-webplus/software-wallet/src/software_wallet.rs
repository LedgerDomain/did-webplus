use crate::REQWEST_CLIENT;
use did_webplus_core::{
    DIDDocument, DIDDocumentCreateParams, DIDDocumentUpdateParams, DIDFullyQualified, DIDStr,
    KeyPurpose, KeyPurposeFlags,
};
use did_webplus_wallet::{Error, Result, Wallet};
use did_webplus_wallet_store::{
    LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyUsage, PrivKeyUsageRecord,
    VerificationMethodRecord, WalletStorage, WalletStorageCtx,
};
use selfsign::Signer;
use std::{borrow::Cow, sync::Arc};

#[derive(Clone)]
pub struct SoftwareWallet {
    ctx: WalletStorageCtx,
    wallet_storage_a: Arc<dyn WalletStorage>,
}

impl SoftwareWallet {
    pub async fn create(
        transaction: &mut dyn storage_traits::TransactionDynT,
        wallet_storage_a: Arc<dyn WalletStorage>,
        wallet_name_o: Option<String>,
    ) -> Result<Self> {
        let wallet_storage_ctx = wallet_storage_a
            .create_wallet(Some(transaction), wallet_name_o)
            .await?;
        Ok(Self {
            ctx: wallet_storage_ctx,
            wallet_storage_a,
        })
    }
    pub async fn open(
        transaction: &mut dyn storage_traits::TransactionDynT,
        wallet_storage_a: Arc<dyn WalletStorage>,
        wallet_uuid: &uuid::Uuid,
    ) -> Result<Self> {
        let (wallet_storage_ctx, _wallet_record) = wallet_storage_a
            .get_wallet(Some(transaction), wallet_uuid)
            .await?
            .ok_or_else(|| {
                Error::NotFound(format!("Wallet with wallet_uuid {}", wallet_uuid).into())
            })?;
        Ok(Self {
            ctx: wallet_storage_ctx,
            wallet_storage_a,
        })
    }
    async fn fetch_did_internal(
        &self,
        did: &DIDStr,
        vdr_scheme: &'static str,
    ) -> Result<did_webplus_core::DIDDocument> {
        // Note the version of the known latest DID document.  This will only differ from the actual latest
        // version if more than one wallet controls the DID.

        // Retrieve any unfetched updates to the DID.
        let did_resolver = did_webplus_resolver::DIDResolverFull {
            did_doc_store: did_webplus_doc_store::DIDDocStore::new(
                self.wallet_storage_a.clone().as_did_doc_storage_a(),
            ),
            http_scheme: vdr_scheme,
        };
        use did_webplus_resolver::DIDResolver;
        let (did_document, _did_doc_metadata) = did_resolver
            .resolve_did_document(
                did.as_str(),
                did_webplus_core::RequestedDIDDocumentMetadata::none(),
            )
            .await
            .map_err(|e| Error::DIDFetchError(format!("DID: {}, error was: {}", did, e).into()))?;

        Ok(did_document)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Wallet for SoftwareWallet {
    async fn create_did(&self, vdr_did_create_endpoint: &str) -> Result<DIDFullyQualified> {
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
        let scheme: &'static str = match vdr_did_create_endpoint_url.scheme() {
            "http" => "http",
            "https" => "https",
            _ => {
                return Err(Error::InvalidVDRDIDCreateURL(
                    format!(
                        "VDR DID Create endpoint URL {:?} expected scheme \"http\" or \"https\"",
                        vdr_did_create_endpoint
                    )
                    .into(),
                ));
            }
        };
        if vdr_did_create_endpoint_url.host_str().is_none() {
            return Err(Error::InvalidVDRDIDCreateURL(
                format!(
                    "VDR DID Create endpoint URL {:?} has no host",
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
        let created_at = time::OffsetDateTime::now_utc();
        // TODO: Somehow iterate?
        let priv_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::AssertionMethod => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::KeyAgreement => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityInvocation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityDelegation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        };
        // TODO: Somehow iterate?
        let pub_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => priv_key_m[KeyPurpose::Authentication].verifying_key(),
            KeyPurpose::AssertionMethod => priv_key_m[KeyPurpose::AssertionMethod].verifying_key(),
            KeyPurpose::KeyAgreement => priv_key_m[KeyPurpose::KeyAgreement].verifying_key(),
            KeyPurpose::CapabilityInvocation => priv_key_m[KeyPurpose::CapabilityInvocation].verifying_key(),
            KeyPurpose::CapabilityDelegation => priv_key_m[KeyPurpose::CapabilityDelegation].verifying_key(),
        };

        // Form the self-signed-and-hashed root DID document.
        let did_document = DIDDocument::create_root(
            DIDDocumentCreateParams {
                did_host: vdr_did_create_endpoint_url.host_str().unwrap().into(),
                did_port_o: vdr_did_create_endpoint_url.port(),
                did_path_o,
                valid_from: time::OffsetDateTime::now_utc(),
                public_key_set: did_webplus_core::PublicKeySet {
                    authentication_v: vec![&pub_key_m[KeyPurpose::Authentication]],
                    assertion_method_v: vec![&pub_key_m[KeyPurpose::AssertionMethod]],
                    key_agreement_v: vec![&pub_key_m[KeyPurpose::KeyAgreement]],
                    // Note that this is the one being used to self-sign the root DIDDocument.
                    capability_invocation_v: vec![&pub_key_m[KeyPurpose::CapabilityInvocation]],
                    capability_delegation_v: vec![&pub_key_m[KeyPurpose::CapabilityDelegation]],
                },
            },
            &selfhash::Blake3,
            &priv_key_m[KeyPurpose::CapabilityInvocation],
        )
        .expect("pass");
        assert!(did_document.self_signature_verifier_o.is_some());
        let did = did_document.did.as_did_str();

        let mut transaction_b = self
            .wallet_storage_a
            .begin_transaction()
            .await
            .map_err(|e| Error::WalletStorageError(e.into()))?;

        // Serialize DID doc as JCS (JSON Canonicalization Scheme), then
        // POST the DID document to the VDR to create the DID.
        // TODO: Could parallelize a lot of this stuff (VDR request vs database ops)
        {
            let did_document_jcs = did_document
                .serialize_canonically()
                .expect("this shouldn't happen");
            // Store the DID doc.  Note that this will also ingest the verification methods from the DID doc,
            // which represents the control of the versioned DID.
            self.wallet_storage_a
                .add_did_document(
                    Some(transaction_b.as_mut()),
                    &did_document,
                    did_document_jcs.as_str(),
                )
                .await?;

            // HTTP POST is for DID create operation.
            REQWEST_CLIENT
                .clone()
                .post(did.resolution_url(scheme))
                .body(did_document_jcs)
                .send()
                .await
                .map_err(|e| Error::HTTPRequestError(e.to_string().into()))?
                .error_for_status()
                .map_err(|e| Error::HTTPOperationStatus(e.to_string().into()))?;
        }

        // Store the priv keys
        for key_purpose in KeyPurpose::VARIANTS {
            use selfsign::Verifier;
            self.wallet_storage_a
                .add_priv_key(
                    Some(transaction_b.as_mut()),
                    &self.ctx,
                    PrivKeyRecord {
                        pub_key: priv_key_m[key_purpose]
                            .verifying_key()
                            .to_keri_verifier()
                            .into_owned(),
                        key_purpose_restriction_o: Some(KeyPurposeFlags::from(key_purpose)),
                        created_at,
                        last_used_at_o: Some(created_at),
                        usage_count: 1,
                        deleted_at_o: None,
                        private_key_bytes_o: Some(
                            priv_key_m[key_purpose].to_private_key_bytes().to_owned(),
                        ),
                    },
                )
                .await?;
        }

        // Add the priv key usage for the DIDCreate.
        let controlled_did = did.with_queries(did_document.self_hash(), 0);
        let controlled_did_with_key_id = controlled_did
            .with_fragment(did_document.self_signature_verifier_o.as_deref().unwrap());
        self.wallet_storage_a
            .add_priv_key_usage(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &PrivKeyUsageRecord {
                    pub_key: did_document
                        .self_signature_verifier_o
                        .as_ref()
                        .unwrap()
                        .clone(),
                    used_at: created_at,
                    usage: PrivKeyUsage::DIDCreate {
                        created_did_o: Some(did.to_owned()),
                    },
                    verification_method_and_purpose_o: Some((
                        controlled_did_with_key_id,
                        KeyPurpose::CapabilityInvocation,
                    )),
                },
            )
            .await?;

        transaction_b
            .commit()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;

        Ok(controlled_did)
    }
    // TODO: Figure out how to update any other local doc stores.
    async fn fetch_did(&self, did: &DIDStr, vdr_scheme: &'static str) -> Result<()> {
        self.fetch_did_internal(did, vdr_scheme).await?;
        Ok(())
    }
    async fn update_did(
        &self,
        did: &DIDStr,
        vdr_scheme: &'static str,
    ) -> Result<DIDFullyQualified> {
        assert!(vdr_scheme == "https" || vdr_scheme == "http");

        // Fetch external updates to the DID before updating it.  This is only relevant if more than one wallet
        // controls the DID.
        let latest_did_document = self.fetch_did_internal(did, vdr_scheme).await?;

        // Rotate the appropriate set of keys.  Record the creation timestamp.
        let now_utc = time::OffsetDateTime::now_utc();
        // TODO: Somehow iterate?
        let priv_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::AssertionMethod => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::KeyAgreement => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityInvocation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
            KeyPurpose::CapabilityDelegation => ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        };
        // TODO: Somehow iterate?
        use selfsign::Verifier;
        let pub_key_m = enum_map::enum_map! {
            KeyPurpose::Authentication => priv_key_m[KeyPurpose::Authentication].verifying_key().to_keri_verifier().into_owned(),
            KeyPurpose::AssertionMethod => priv_key_m[KeyPurpose::AssertionMethod].verifying_key().to_keri_verifier().into_owned(),
            KeyPurpose::KeyAgreement => priv_key_m[KeyPurpose::KeyAgreement].verifying_key().to_keri_verifier().into_owned(),
            KeyPurpose::CapabilityInvocation => priv_key_m[KeyPurpose::CapabilityInvocation].verifying_key().to_keri_verifier().into_owned(),
            KeyPurpose::CapabilityDelegation => priv_key_m[KeyPurpose::CapabilityDelegation].verifying_key().to_keri_verifier().into_owned(),
        };

        let mut transaction_b = self
            .wallet_storage_a
            .begin_transaction()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;
        // Select all the locally-stored keys that are in the latest DID document, so that they can be
        // retired, the CapabilityInvocation key selected for signing the update, and the new keys stored.
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
        // If there are no matching locally controlled verification methods, then this means that the DID
        // doc has been changed by another wallet that controls this DID, and this wallet no longer controls
        // any keys present in the DID doc, and so there's no way for it to proceed with the DID update.
        if locally_controlled_verification_method_v.is_empty() {
            return Err(Error::NoSuitablePrivKeyFound(format!("this wallet has no locally-controlled verification methods for {}, so DID cannot be updated by this wallet; latest DID doc has selfHash {} and versionId {}", did, latest_did_document.self_hash(), latest_did_document.version_id).into()));
        }

        // Select the appropriate key to self-sign the updated DID document.
        let (_, priv_key_record_for_update) = locally_controlled_verification_method_v.iter().find(|(verification_method_record, _priv_key_record)| verification_method_record.key_purpose_flags.contains(KeyPurpose::CapabilityInvocation)).ok_or_else(|| Error::NoSuitablePrivKeyFound(format!("this wallet has no locally-controlled {} verification method for {}, so DID cannot be updated by this wallet; latest DID doc has selfHash {} and versionId {}", KeyPurpose::CapabilityInvocation, did, latest_did_document.self_hash(), latest_did_document.version_id).into()))?;
        let priv_key_for_update = priv_key_record_for_update
            .private_key_bytes_o
            .as_ref()
            .expect(
                "programmer error: priv_key_bytes_o was expected to be Some(_); i.e. not deleted",
            );

        // Form and self-sign-and-hash the updated DID document.
        // TODO: Allow for other verification methods that were added by other wallets.
        let updated_did_document = DIDDocument::update_from_previous(
            &latest_did_document,
            DIDDocumentUpdateParams {
                valid_from: now_utc,
                public_key_set: did_webplus_core::PublicKeySet {
                    authentication_v: vec![&pub_key_m[KeyPurpose::Authentication].as_ref()],
                    assertion_method_v: vec![&pub_key_m[KeyPurpose::AssertionMethod].as_ref()],
                    key_agreement_v: vec![&pub_key_m[KeyPurpose::KeyAgreement].as_ref()],
                    capability_invocation_v: vec![
                        &pub_key_m[KeyPurpose::CapabilityInvocation].as_ref()
                    ],
                    capability_delegation_v: vec![
                        &pub_key_m[KeyPurpose::CapabilityDelegation].as_ref()
                    ],
                },
            },
            &selfhash::Blake3,
            priv_key_for_update,
        )?;

        // Serialize DID doc as JCS (JSON Canonicalization Scheme), then
        // PUT the DID document to the VDR to update the DID.
        // TODO: Could parallelize a lot of this stuff (VDR request vs database ops)
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

            // HTTP PUT is for DID update operation.
            REQWEST_CLIENT
                .clone()
                .put(did.resolution_url(vdr_scheme))
                .body(updated_did_document_jcs)
                .send()
                .await
                .map_err(|e| Error::HTTPRequestError(e.to_string().into()))?
                .error_for_status()
                .map_err(|e| Error::HTTPOperationStatus(e.to_string().into()))?;
        }

        // Store the priv keys
        for key_purpose in KeyPurpose::VARIANTS {
            self.wallet_storage_a
                .add_priv_key(
                    Some(transaction_b.as_mut()),
                    &self.ctx,
                    PrivKeyRecord {
                        pub_key: priv_key_m[key_purpose]
                            .verifying_key()
                            .to_keri_verifier()
                            .into_owned(),
                        key_purpose_restriction_o: Some(KeyPurposeFlags::from(key_purpose)),
                        created_at: now_utc,
                        last_used_at_o: None,
                        usage_count: 0,
                        deleted_at_o: None,
                        private_key_bytes_o: Some(
                            priv_key_m[key_purpose].to_private_key_bytes().to_owned(),
                        ),
                    },
                )
                .await?;
        }

        // Add the priv key usage for the DIDUpdate
        let controlled_did = did.with_queries(
            updated_did_document.self_hash(),
            updated_did_document.version_id,
        );
        let controlled_did_with_key_id = controlled_did.with_fragment(
            updated_did_document
                .self_signature_verifier_o
                .as_deref()
                .unwrap(),
        );
        self.wallet_storage_a
            .add_priv_key_usage(
                Some(transaction_b.as_mut()),
                &self.ctx,
                &PrivKeyUsageRecord {
                    pub_key: updated_did_document
                        .self_signature_verifier_o
                        .as_ref()
                        .unwrap()
                        .clone(),
                    used_at: now_utc,
                    usage: PrivKeyUsage::DIDUpdate {
                        updated_did_fully_qualified_o: Some(controlled_did.clone()),
                    },
                    verification_method_and_purpose_o: Some((
                        controlled_did_with_key_id,
                        KeyPurpose::CapabilityInvocation,
                    )),
                },
            )
            .await?;

        // Retire the old priv keys
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

        transaction_b
            .commit()
            .await
            .map_err(|e| did_webplus_wallet_store::Error::from(e))?;

        Ok(controlled_did)
    }
    async fn get_locally_controlled_verification_methods(
        &self,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<Vec<(VerificationMethodRecord, Box<dyn selfsign::Signer>)>> {
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
                let signer_b: Box<dyn selfsign::Signer> =
                    Box::new(priv_key_record.private_key_bytes_o.unwrap());
                (verification_method_record, signer_b)
            })
            .collect())
    }
}
