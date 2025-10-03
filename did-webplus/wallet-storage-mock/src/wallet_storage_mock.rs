#![allow(dead_code)]

use crate::db::{
    Index, IndexedRowT, OnConflict, RowId, RowT, SigilT, Table, TableError, TableResult,
    TableWithPrimaryKey,
};
use did_webplus_core::{
    now_utc_milliseconds, DIDDocument, DIDKeyResourceFullyQualifiedStr, DIDStr, DID,
};
use did_webplus_doc_store::{DIDDocRecord, DIDDocRecordFilter};
use did_webplus_wallet_store::{
    LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyRecordFilter,
    PrivKeyUsageRecord, PrivKeyUsageRecordFilter, VerificationMethodRecord, WalletRecord,
    WalletRecordFilter, WalletStorageCtx,
};
use std::sync::{Arc, RwLock};

/// Sigil representing the wallets table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Wallets;

impl SigilT for Wallets {}

/// Corresponds to `wallets` table in sqlite impl.
#[derive(Clone, Debug)]
struct WalletRow {
    wallet_uuid: uuid::Uuid,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
    deleted_at_o: Option<time::OffsetDateTime>,
    wallet_name_o: Option<String>,
}

impl RowT<uuid::Uuid> for WalletRow {
    fn primary_key(&self) -> &uuid::Uuid {
        &self.wallet_uuid
    }
}

type WalletsTable = TableWithPrimaryKey<Wallets, uuid::Uuid, WalletRow>;

/// Sigil representing the priv_keys table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct PrivKeys;

impl SigilT for PrivKeys {}

/// Corresponds to `priv_keys` table in sqlite impl.
#[derive(Clone, Debug)]
struct PrivKeyRow {
    // This awkwardness is so that the primary key can be returned by reference without any gymnastics.
    wallets_rowid_pub_key: (RowId<Wallets>, mbx::MBPubKey),
    hashed_pub_key: String,
    key_type: signature_dyn::KeyType,
    did_restriction_o: Option<String>,
    key_purpose_restriction_o: Option<did_webplus_core::KeyPurposeFlags>,
    created_at: time::OffsetDateTime,
    last_used_at_o: Option<time::OffsetDateTime>,
    max_usage_count_o: Option<u32>,
    usage_count: u32,
    deleted_at_o: Option<time::OffsetDateTime>,
    priv_key_format_o: Option<String>,
    priv_key_bytes_o: Option<Vec<u8>>,
    comment_o: Option<String>,
}

impl PrivKeyRow {
    pub fn from_priv_key_record(ctx: &WalletStorageCtx, priv_key_record: PrivKeyRecord) -> Self {
        let wallets_row_id = RowId::from(ctx.wallets_rowid as usize);
        let key_type = priv_key_record.pub_key.try_into_key_type().unwrap();
        let (priv_key_format_o, priv_key_bytes_o) =
            if let Some(signer_bytes) = priv_key_record.private_key_bytes_o {
                (
                    Some("signature_dyn::SignerBytes".to_string()),
                    Some(signer_bytes.bytes().to_vec()),
                )
            } else {
                (None, None)
            };
        PrivKeyRow {
            wallets_rowid_pub_key: (wallets_row_id, priv_key_record.pub_key),
            hashed_pub_key: priv_key_record.hashed_pub_key,
            key_type,
            did_restriction_o: priv_key_record.did_restriction_o,
            key_purpose_restriction_o: priv_key_record.key_purpose_restriction_o,
            created_at: priv_key_record.created_at,
            last_used_at_o: priv_key_record.last_used_at_o,
            max_usage_count_o: priv_key_record.max_usage_count_o,
            usage_count: priv_key_record.usage_count,
            deleted_at_o: priv_key_record.deleted_at_o,
            priv_key_format_o,
            priv_key_bytes_o,
            comment_o: priv_key_record.comment_o,
        }
    }
}

impl RowT<(RowId<Wallets>, mbx::MBPubKey)> for PrivKeyRow {
    fn primary_key(&self) -> &(RowId<Wallets>, mbx::MBPubKey) {
        &self.wallets_rowid_pub_key
    }
}

impl TryFrom<PrivKeyRow> for PrivKeyRecord {
    type Error = did_webplus_wallet_store::Error;
    fn try_from(priv_key_row: PrivKeyRow) -> Result<Self, Self::Error> {
        assert_eq!(
            priv_key_row.priv_key_format_o.as_deref(),
            Some("signature_dyn::SignerBytes")
        );
        let private_key_bytes_o = if let Some(priv_key_bytes) = priv_key_row.priv_key_bytes_o {
            Some(
                signature_dyn::SignerBytes::new(priv_key_row.key_type, priv_key_bytes.into())
                    .map_err(|e| {
                        did_webplus_wallet_store::Error::RecordCorruption(e.to_string().into())
                    })?,
            )
        } else {
            None
        };
        Ok(PrivKeyRecord {
            pub_key: priv_key_row.wallets_rowid_pub_key.1,
            hashed_pub_key: priv_key_row.hashed_pub_key,
            did_restriction_o: priv_key_row.did_restriction_o,
            key_purpose_restriction_o: priv_key_row.key_purpose_restriction_o,
            created_at: priv_key_row.created_at,
            last_used_at_o: priv_key_row.last_used_at_o,
            max_usage_count_o: priv_key_row.max_usage_count_o,
            usage_count: priv_key_row.usage_count,
            deleted_at_o: priv_key_row.deleted_at_o,
            private_key_bytes_o,
            comment_o: priv_key_row.comment_o,
        })
    }
}

type PrivKeysTable = TableWithPrimaryKey<PrivKeys, (RowId<Wallets>, mbx::MBPubKey), PrivKeyRow>;

/// Sigil representing the priv_key_usages table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct PrivKeyUsages;

impl SigilT for PrivKeyUsages {}

/// Corresponds to `priv_key_usages` table in sqlite impl.
#[derive(Clone, Debug)]
struct PrivKeyUsageRow {
    wallets_row_id: RowId<Wallets>,
    priv_key_usage_record: PrivKeyUsageRecord,
}

impl PrivKeyUsageRow {
    pub fn from_priv_key_usage_record(
        ctx: &WalletStorageCtx,
        priv_key_usage_record: PrivKeyUsageRecord,
    ) -> Self {
        let wallets_row_id = RowId::from(ctx.wallets_rowid as usize);
        Self {
            wallets_row_id,
            priv_key_usage_record,
        }
    }
}

type PrivKeyUsagesTable = Table<PrivKeyUsages, PrivKeyUsageRow>;

/// Sigil representing the did_documents table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct DIDDocuments;

impl SigilT for DIDDocuments {}

/// Corresponds to `did_documents` table in sqlite impl.
#[derive(Clone, Debug)]
struct DIDDocumentRow {
    self_hash: mbx::MBHash,
    did: did_webplus_core::DID,
    version_id: u32,
    valid_from: time::OffsetDateTime,
    did_documents_jsonl_octet_length: u64,
    did_document_jcs: String,
}

impl From<&DIDDocumentRow> for DIDDocRecord {
    fn from(did_document_row: &DIDDocumentRow) -> Self {
        DIDDocRecord {
            self_hash: did_document_row.self_hash.to_string(),
            did: did_document_row.did.to_string(),
            version_id: did_document_row.version_id as i64,
            valid_from: did_document_row.valid_from,
            did_documents_jsonl_octet_length: did_document_row.did_documents_jsonl_octet_length
                as i64,
            did_document_jcs: did_document_row.did_document_jcs.clone(),
        }
    }
}
type DIDDocumentsTable = Table<DIDDocuments, DIDDocumentRow>;

/// Sigil representing the did_documents table's (did, self_hash) index.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct DIDDocumentsDIDSelfHash;

impl SigilT for DIDDocumentsDIDSelfHash {}

impl IndexedRowT<DIDDocumentsDIDSelfHash> for DIDDocumentRow {
    type IndexKey = (did_webplus_core::DID, mbx::MBHash);
    fn index_key(&self) -> Self::IndexKey {
        (self.did.clone(), self.self_hash.clone())
    }
}

type DIDDocumentsDIDSelfHashIndex =
    Index<DIDDocumentsDIDSelfHash, DIDDocuments, (did_webplus_core::DID, mbx::MBHash)>;

/// Sigil representing the did_documents table's (did, version_id) index.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct DIDDocumentsDIDVersionId;

impl SigilT for DIDDocumentsDIDVersionId {}

impl IndexedRowT<DIDDocumentsDIDVersionId> for DIDDocumentRow {
    type IndexKey = (did_webplus_core::DID, u32);
    fn index_key(&self) -> Self::IndexKey {
        (self.did.clone(), self.version_id)
    }
}

type DIDDocumentsDIDVersionIdIndex =
    Index<DIDDocumentsDIDVersionId, DIDDocuments, (did_webplus_core::DID, u32)>;

/// Sigil representing the did_documents table's (did, valid_from) index.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct DIDDocumentsDIDValidFrom;

impl SigilT for DIDDocumentsDIDValidFrom {}

impl IndexedRowT<DIDDocumentsDIDValidFrom> for DIDDocumentRow {
    type IndexKey = (did_webplus_core::DID, time::OffsetDateTime);
    fn index_key(&self) -> Self::IndexKey {
        (self.did.clone(), self.valid_from)
    }
}

type DIDDocumentsDIDValidFromIndex =
    Index<DIDDocumentsDIDValidFrom, DIDDocuments, (did_webplus_core::DID, time::OffsetDateTime)>;

/// Sigil representing the verification_methods table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct VerificationMethods;

impl SigilT for VerificationMethods {}

/// Corresponds to `verification_methods` table in sqlite impl.
#[derive(Clone, Debug)]
struct VerificationMethodRow {
    // This awkwardness is so that the primary key can be returned by reference without any gymnastics.
    did_documents_row_id_and_key_id_fragment: (RowId<DIDDocuments>, String),
    controller: DID,
    pub_key: mbx::MBPubKey,
    key_purpose_flags: did_webplus_core::KeyPurposeFlags,
}

impl RowT<(RowId<DIDDocuments>, String)> for VerificationMethodRow {
    fn primary_key(&self) -> &(RowId<DIDDocuments>, String) {
        &self.did_documents_row_id_and_key_id_fragment
    }
}

type VerificationMethodsTable =
    TableWithPrimaryKey<VerificationMethods, (RowId<DIDDocuments>, String), VerificationMethodRow>;

#[derive(Clone, Debug)]
struct WalletStorageMockState {
    wallets_table: WalletsTable,
    priv_keys_table: PrivKeysTable,
    priv_key_usages_table: PrivKeyUsagesTable,
    did_documents_table: DIDDocumentsTable,
    did_documents_did_self_hash_index: DIDDocumentsDIDSelfHashIndex,
    did_documents_did_version_id_index: DIDDocumentsDIDVersionIdIndex,
    did_documents_did_valid_from_index: DIDDocumentsDIDValidFromIndex,
    verification_methods_table: VerificationMethodsTable,
}

impl WalletStorageMockState {
    fn new() -> Self {
        Self {
            wallets_table: WalletsTable::new(),
            priv_keys_table: PrivKeysTable::new(),
            priv_key_usages_table: PrivKeyUsagesTable::new(),
            did_documents_table: DIDDocumentsTable::new(),
            did_documents_did_self_hash_index: DIDDocumentsDIDSelfHashIndex::new(),
            did_documents_did_version_id_index: DIDDocumentsDIDVersionIdIndex::new(),
            did_documents_did_valid_from_index: DIDDocumentsDIDValidFromIndex::new(),
            verification_methods_table: VerificationMethodsTable::new(),
        }
    }
    fn add_did_document(
        &mut self,
        did_document: DIDDocument,
        did_document_jcs: String,
    ) -> TableResult<()> {
        let latest_did_documents_jsonl_octet_length = self
            .get_latest_did_document(&did_document.did)?
            .map(|(_, did_document_row)| did_document_row.did_documents_jsonl_octet_length)
            .unwrap_or(0);
        let row = DIDDocumentRow {
            self_hash: did_document.self_hash.clone(),
            did: did_document.did.clone(),
            version_id: did_document.version_id,
            valid_from: did_document.valid_from,
            did_documents_jsonl_octet_length: latest_did_documents_jsonl_octet_length
                + did_document_jcs.len() as u64
                + 1,
            did_document_jcs,
        };
        let did_documents_row_id = self.did_documents_table.insert_with_index_3(
            row,
            &mut self.did_documents_did_self_hash_index,
            &mut self.did_documents_did_version_id_index,
            &mut self.did_documents_did_valid_from_index,
        )?;

        // Now insert all the verification methods.
        for verification_method in did_document
            .public_key_material
            .verification_method_v
            .iter()
        {
            let key_id_fragment = verification_method.id.fragment();
            let pub_key = mbx::MBPubKey::try_from(&verification_method.public_key_jwk)
                .map_err(|x| x.to_string())?;
            let key_purpose_flags = did_document
                .public_key_material
                .key_purpose_flags_for_key_id_fragment(verification_method.id.fragment());

            let verification_method_row = VerificationMethodRow {
                did_documents_row_id_and_key_id_fragment: (
                    did_documents_row_id,
                    key_id_fragment.to_owned(),
                ),
                controller: verification_method.controller.clone(),
                pub_key,
                key_purpose_flags,
            };
            self.verification_methods_table
                .insert(verification_method_row, OnConflict::Abort)?;
        }
        Ok(())
    }
    fn get_did_document_with_self_hash(
        &self,
        did: &DIDStr,
        self_hash: &mbx::MBHashStr,
    ) -> TableResult<Option<(RowId<DIDDocuments>, &DIDDocumentRow)>> {
        Ok(
            self.did_documents_did_self_hash_index.select(
                &self.did_documents_table,
                &(did.to_owned(), self_hash.to_owned()),
            ), // .map(|(row_id, row)| (row_id, row.clone())))
        )
    }
    fn get_did_document_with_version_id(
        &self,
        did: &DIDStr,
        version_id: u32,
    ) -> TableResult<Option<(RowId<DIDDocuments>, &DIDDocumentRow)>> {
        Ok(
            self.did_documents_did_version_id_index
                .select(&self.did_documents_table, &(did.to_owned(), version_id)), // .map(|(row_id, row)| (row_id, row.clone())))
        )
    }
    fn get_latest_did_document(
        &self,
        did: &DIDStr,
    ) -> TableResult<Option<(RowId<DIDDocuments>, &DIDDocumentRow)>> {
        Ok(self
            .did_documents_table
            .row_iter()
            .filter(|(_row_id, row)| row.did.as_did_str() == did)
            .max_by_key(|(_row_id, row)| row.valid_from)
            // .map(|(row_id, row)| (*row_id, row.clone())))
            .map(|(row_id, row)| (*row_id, row)))
    }
    // TODO: Replace return type with appropriate Iterator
    fn get_did_documents(&self) -> TableResult<Vec<(RowId<DIDDocuments>, &DIDDocumentRow)>> {
        Ok(self
            .did_documents_table
            .row_iter()
            .map(|(row_id, row)| (*row_id, row))
            .collect())
    }
    fn get_did_doc_records_for_did_documents_jsonl_range(
        &self,
        did: &DIDStr,
        range_begin_inclusive_o: Option<u64>,
        range_end_exclusive_o: Option<u64>,
    ) -> TableResult<Vec<(RowId<DIDDocuments>, &DIDDocumentRow)>> {
        let range_begin_inclusive = range_begin_inclusive_o.unwrap_or(0);
        let range_end_exclusive = range_end_exclusive_o.unwrap_or(i64::MAX as u64);

        if range_begin_inclusive >= range_end_exclusive {
            // If the range is empty (or invalid), return an empty vector.
            return Ok(Vec::new());
        }

        Ok(self
            .did_documents_table
            .row_iter()
            .filter(|(_row_id, row)| {
                row.did.as_did_str() == did
                    && range_begin_inclusive < row.did_documents_jsonl_octet_length
                    && row.did_documents_jsonl_octet_length
                        - (row.did_document_jcs.len() as u64 + 1)
                        < range_end_exclusive
            })
            .map(|(row_id, row)| (*row_id, row))
            .collect())
    }
    fn add_wallet(&mut self, wallet_record: WalletRecord) -> TableResult<RowId<Wallets>> {
        let row = WalletRow {
            wallet_uuid: wallet_record.wallet_uuid,
            created_at: wallet_record.created_at,
            updated_at: wallet_record.updated_at,
            deleted_at_o: wallet_record.deleted_at_o,
            wallet_name_o: wallet_record.wallet_name_o,
        };
        self.wallets_table.insert(row, OnConflict::Abort)
    }
    fn get_wallet(
        &self,
        wallet_uuid: &uuid::Uuid,
    ) -> TableResult<Option<(RowId<Wallets>, &WalletRow)>> {
        Ok(self
            .wallets_table
            .select(wallet_uuid)
            .map(|(row_id, row)| (row_id, row)))
    }
    // TODO: Replace return type with appropriate Iterator
    fn get_wallets(&self) -> TableResult<Vec<(RowId<Wallets>, &WalletRow)>> {
        Ok(self
            .wallets_table
            .row_iter()
            .map(|(row_id, row)| (*row_id, row))
            .collect())
    }
    fn add_priv_key(
        &mut self,
        ctx: &WalletStorageCtx,
        priv_key_record: PrivKeyRecord,
    ) -> TableResult<RowId<PrivKeys>> {
        let row = PrivKeyRow::from_priv_key_record(ctx, priv_key_record);
        self.priv_keys_table.insert(row, OnConflict::Abort)
    }
    fn delete_priv_key(
        &mut self,
        ctx: &WalletStorageCtx,
        pub_key: &mbx::MBPubKeyStr,
    ) -> TableResult<()> {
        let wallets_row_id = RowId::from(ctx.wallets_rowid as usize);
        let pub_key = pub_key.to_owned();
        // self.priv_keys_table.remove(&(wallets_row_id, pub_key))?;
        self.priv_keys_table
            .update(&(wallets_row_id, pub_key), |row| {
                let mut row = row.clone();
                row.deleted_at_o = Some(now_utc_milliseconds());
                Ok(row)
            })?;
        Ok(())
    }
    fn get_priv_key(
        &self,
        ctx: &WalletStorageCtx,
        pub_key: &mbx::MBPubKeyStr,
    ) -> TableResult<Option<(RowId<PrivKeys>, &PrivKeyRow)>> {
        let wallets_row_id = RowId::from(ctx.wallets_rowid as usize);
        let pub_key = pub_key.to_owned();
        Ok(self
            .priv_keys_table
            .select(&(wallets_row_id, pub_key))
            .map(|(row_id, row)| (row_id, row)))
    }
    fn get_priv_keys(
        &self,
        ctx: &WalletStorageCtx,
    ) -> TableResult<Vec<(RowId<PrivKeys>, &PrivKeyRow)>> {
        let wallets_row_id = RowId::from(ctx.wallets_rowid as usize);
        Ok(self
            .priv_keys_table
            .row_iter()
            .filter(|(_row_id, row)| row.wallets_rowid_pub_key.0 == wallets_row_id)
            .map(|(row_id, row)| (*row_id, row))
            .collect())
    }
    fn add_priv_key_usage(
        &mut self,
        ctx: &WalletStorageCtx,
        priv_key_usage_record: PrivKeyUsageRecord,
    ) -> RowId<PrivKeyUsages> {
        let row = PrivKeyUsageRow::from_priv_key_usage_record(ctx, priv_key_usage_record);
        self.priv_key_usages_table.insert(row)
    }
    fn get_priv_key_usages(
        &self,
        ctx: &WalletStorageCtx,
    ) -> TableResult<Vec<(RowId<PrivKeyUsages>, &PrivKeyUsageRow)>> {
        let wallets_row_id = RowId::from(ctx.wallets_rowid as usize);
        Ok(self
            .priv_key_usages_table
            .row_iter()
            .filter(|(_row_id, row)| row.wallets_row_id == wallets_row_id)
            .map(|(row_id, row)| (*row_id, row))
            .collect())
    }
    fn get_locally_controlled_verification_methods(
        &self,
        ctx: &WalletStorageCtx,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> TableResult<Vec<LocallyControlledVerificationMethod>> {
        let wallets_row_id = RowId::from(ctx.wallets_rowid as usize);
        let mut locally_controlled_verification_method_v = Vec::new();
        for (_verification_methods_row_id, verification_method_row) in
            self.verification_methods_table.row_iter()
        {
            // INNER JOIN DIDDocuments on did_documents_row_id
            let did_document_row = self.did_documents_table.select_by_row_id(verification_method_row.did_documents_row_id_and_key_id_fragment.0).expect("programmer error: DIDDocuments and VerificationMethods tables are inconsistent");
            // INNER JOIN PrivKeys on pub_key
            let (_priv_key_row_id, priv_key_row) = self
                .priv_keys_table
                .select(&(wallets_row_id, verification_method_row.pub_key.clone()))
                .expect(
                    "programmer error: PrivKeys and VerificationMethods tables are inconsistent",
                );

            // Apply filters.  Note that some of these could be moved earlier.  But for clarity, do them all here.
            if let Some(did) = locally_controlled_verification_method_filter
                .did_o
                .as_deref()
            {
                if did_document_row.did.as_did_str() != did {
                    continue;
                }
            }
            if let Some(version_id) = locally_controlled_verification_method_filter.version_id_o {
                if did_document_row.version_id != version_id {
                    continue;
                }
            }
            if let Some(key_purpose) = locally_controlled_verification_method_filter.key_purpose_o {
                if !verification_method_row
                    .key_purpose_flags
                    .contains(key_purpose)
                {
                    continue;
                }
            }
            if let Some(key_id) = locally_controlled_verification_method_filter
                .key_id_o
                .as_deref()
            {
                if verification_method_row
                    .did_documents_row_id_and_key_id_fragment
                    .1
                    .as_str()
                    != key_id
                {
                    continue;
                }
            }
            // It passed all filters, so add it to the results.
            let locally_controlled_verification_method = LocallyControlledVerificationMethod {
                verification_method_record: VerificationMethodRecord {
                    did_key_resource_fully_qualified: verification_method_row
                        .controller
                        .with_queries(&did_document_row.self_hash, did_document_row.version_id)
                        .with_fragment(
                            verification_method_row
                                .did_documents_row_id_and_key_id_fragment
                                .1
                                .as_str(),
                        ),
                    key_purpose_flags: verification_method_row.key_purpose_flags,
                    pub_key: verification_method_row.pub_key.clone(),
                },
                did_document: serde_json::from_str(&did_document_row.did_document_jcs)
                    .expect("programmer error: record corruption"),
                priv_key_record: PrivKeyRecord::try_from(priv_key_row.clone())
                    .map_err(|e| TableError::from(e.to_string()))?,
            };
            locally_controlled_verification_method_v.push(locally_controlled_verification_method);
        }
        Ok(locally_controlled_verification_method_v)
    }
}

struct LocallyControlledVerificationMethod {
    verification_method_record: VerificationMethodRecord,
    did_document: DIDDocument,
    priv_key_record: PrivKeyRecord,
}

#[derive(Clone)]
pub struct WalletStorageMock {
    state_la: Arc<RwLock<WalletStorageMockState>>,
}

impl WalletStorageMock {
    pub fn new() -> Self {
        Self {
            state_la: Arc::new(RwLock::new(WalletStorageMockState::new())),
        }
    }
}

impl std::fmt::Debug for WalletStorageMock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state_g = self.state_la.read().unwrap();
        std::fmt::Debug::fmt(&state_g, f)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for WalletStorageMock {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(Box::new(WalletStorageMockTransaction))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_doc_store::DIDDocStorage for WalletStorageMock {
    async fn add_did_document(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &DIDDocument,
        did_document_jcs: &str,
    ) -> did_webplus_doc_store::Result<()> {
        let mut state_g = self.state_la.write().unwrap();
        state_g.add_did_document(did_document.clone(), did_document_jcs.to_owned())?;
        Ok(())
    }
    async fn add_did_documents(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document_jcs_v: &[&str],
        did_document_v: &[DIDDocument],
    ) -> did_webplus_doc_store::Result<()> {
        let mut state_g = self.state_la.write().unwrap();
        for (&did_document_jcs, did_document) in
            did_document_jcs_v.iter().zip(did_document_v.iter())
        {
            state_g.add_did_document(did_document.clone(), did_document_jcs.to_owned())?;
        }
        Ok(())
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        self_hash: &mbx::MBHashStr,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        Ok(state_g
            .get_did_document_with_self_hash(did, self_hash)?
            .map(|(_, row)| DIDDocRecord::from(row)))
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        version_id: u32,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        Ok(state_g
            .get_did_document_with_version_id(did, version_id)?
            .map(|(_, row)| DIDDocRecord::from(row)))
    }
    async fn get_latest_did_doc_record(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        Ok(state_g
            .get_latest_did_document(did)?
            .map(|(_, row)| DIDDocRecord::from(row)))
    }
    async fn get_did_doc_records(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_doc_record_filter: &DIDDocRecordFilter,
    ) -> did_webplus_doc_store::Result<Vec<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        let mut did_doc_records = Vec::new();
        for (_row_id, row) in state_g.get_did_documents()? {
            // This is a bit wasteful because it allocates unnecessarily before filtering.
            let did_doc_record = DIDDocRecord::from(row);
            if did_doc_record_filter.matches(&did_doc_record) {
                did_doc_records.push(did_doc_record);
            }
        }
        Ok(did_doc_records)
    }
    async fn get_did_doc_records_for_did_documents_jsonl_range(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        range_begin_inclusive_o: Option<u64>,
        range_end_exclusive_o: Option<u64>,
    ) -> did_webplus_doc_store::Result<Vec<DIDDocRecord>> {
        let state_g = self.state_la.read().unwrap();
        let did_doc_record_v = state_g
            .get_did_doc_records_for_did_documents_jsonl_range(
                did,
                range_begin_inclusive_o,
                range_end_exclusive_o,
            )?
            .into_iter()
            .map(|(_, row)| DIDDocRecord::from(row))
            .collect::<Vec<_>>();
        Ok(did_doc_record_v)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_wallet_store::WalletStorage for WalletStorageMock {
    async fn add_wallet(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_record: WalletRecord,
    ) -> did_webplus_wallet_store::Result<WalletStorageCtx> {
        let mut state_g = self.state_la.write().unwrap();
        let wallets_rowid = *state_g.add_wallet(wallet_record)? as i64;
        Ok(WalletStorageCtx { wallets_rowid })
    }
    async fn get_wallet(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_uuid: &uuid::Uuid,
    ) -> did_webplus_wallet_store::Result<Option<(WalletStorageCtx, WalletRecord)>> {
        let state_g = self.state_la.read().unwrap();
        if let Some((wallets_row_id, row)) = state_g.get_wallet(wallet_uuid)? {
            Ok(Some((
                WalletStorageCtx {
                    wallets_rowid: *wallets_row_id as i64,
                },
                WalletRecord {
                    wallet_uuid: row.wallet_uuid,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    deleted_at_o: row.deleted_at_o,
                    wallet_name_o: row.wallet_name_o.clone(),
                },
            )))
        } else {
            Ok(None)
        }
    }
    async fn get_wallets(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_record_filter: &WalletRecordFilter,
    ) -> did_webplus_wallet_store::Result<Vec<(WalletStorageCtx, WalletRecord)>> {
        let state_g = self.state_la.read().unwrap();
        Ok(state_g
            .get_wallets()?
            .into_iter()
            .filter_map(|(row_id, row)| {
                let wallet_storage_ctx = WalletStorageCtx {
                    wallets_rowid: *row_id as i64,
                };
                let wallet_record = WalletRecord {
                    wallet_uuid: row.wallet_uuid,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    deleted_at_o: row.deleted_at_o,
                    wallet_name_o: row.wallet_name_o.clone(),
                };
                if wallet_record_filter.matches(&wallet_record) {
                    Some((wallet_storage_ctx, wallet_record))
                } else {
                    None
                }
            })
            .collect())
    }
    async fn add_priv_key(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_record: PrivKeyRecord,
    ) -> did_webplus_wallet_store::Result<()> {
        let mut state_g = self.state_la.write().unwrap();
        state_g.add_priv_key(ctx, priv_key_record)?;
        Ok(())
    }
    async fn delete_priv_key(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        pub_key: &mbx::MBPubKeyStr,
    ) -> did_webplus_wallet_store::Result<()> {
        let mut state_g = self.state_la.write().unwrap();
        state_g.delete_priv_key(ctx, pub_key)?;
        Ok(())
    }
    async fn get_priv_key(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        pub_key: &mbx::MBPubKeyStr,
    ) -> did_webplus_wallet_store::Result<Option<PrivKeyRecord>> {
        let state_g = self.state_la.read().unwrap();
        if let Some((_row_id, row)) = state_g.get_priv_key(ctx, pub_key)? {
            let priv_key_record = PrivKeyRecord::try_from(row.clone())?;
            Ok(Some(priv_key_record))
        } else {
            Ok(None)
        }
    }
    async fn get_priv_keys(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_record_filter: &PrivKeyRecordFilter,
    ) -> did_webplus_wallet_store::Result<Vec<PrivKeyRecord>> {
        let state_g = self.state_la.read().unwrap();
        let mut priv_key_record_v = Vec::new();
        for (_row_id, row) in state_g.get_priv_keys(ctx)?.into_iter() {
            let priv_key_record = PrivKeyRecord::try_from(row.clone())?;
            if priv_key_record_filter.matches(&priv_key_record) {
                priv_key_record_v.push(priv_key_record);
            }
        }
        Ok(priv_key_record_v)
    }
    async fn add_priv_key_usage(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record: &PrivKeyUsageRecord,
    ) -> did_webplus_wallet_store::Result<()> {
        let mut state_g = self.state_la.write().unwrap();
        state_g.add_priv_key_usage(ctx, priv_key_usage_record.clone());
        Ok(())
    }
    async fn get_priv_key_usages(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record_filter: &PrivKeyUsageRecordFilter,
    ) -> did_webplus_wallet_store::Result<Vec<PrivKeyUsageRecord>> {
        let state_g = self.state_la.read().unwrap();
        let mut priv_key_usage_record_v = Vec::new();
        for (_row_id, row) in state_g.get_priv_key_usages(ctx)?.into_iter() {
            let priv_key_usage_record = row.priv_key_usage_record.clone();
            if priv_key_usage_record_filter.matches(&priv_key_usage_record) {
                priv_key_usage_record_v.push(priv_key_usage_record);
            }
        }
        Ok(priv_key_usage_record_v)
    }
    async fn get_verification_method(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _ctx: &WalletStorageCtx,
        _did_key_resource_fully_qualified: &DIDKeyResourceFullyQualifiedStr,
    ) -> did_webplus_wallet_store::Result<VerificationMethodRecord> {
        unimplemented!();
    }
    async fn get_locally_controlled_verification_methods(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> did_webplus_wallet_store::Result<Vec<(VerificationMethodRecord, PrivKeyRecord)>> {
        let state_g = self.state_la.read().unwrap();
        Ok(state_g
            .get_locally_controlled_verification_methods(
                ctx,
                locally_controlled_verification_method_filter,
            )?
            .into_iter()
            .map(|locally_controlled_verification_method| {
                (
                    locally_controlled_verification_method.verification_method_record,
                    locally_controlled_verification_method.priv_key_record,
                )
            })
            .collect())
    }
    fn as_did_doc_storage(&self) -> &dyn did_webplus_doc_store::DIDDocStorage {
        self
    }
    fn as_did_doc_storage_a(self: Arc<Self>) -> Arc<dyn did_webplus_doc_store::DIDDocStorage> {
        self
    }
}

// TODO: Maybe track if this has been committed or not, so that Drop can determine if
// it would be a rollback (which would mean that it would have to panic because rollback
// is not currently supported).
#[derive(Clone, Debug)]
struct WalletStorageMockTransaction;

impl std::ops::Drop for WalletStorageMockTransaction {
    fn drop(&mut self) {
        // Nothing to do
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::TransactionDynT for WalletStorageMockTransaction {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    async fn commit(self: Box<Self>) -> storage_traits::Result<()> {
        Ok(())
    }
    async fn rollback(self: Box<Self>) -> storage_traits::Result<()> {
        panic!("Transaction rollback is not supported by WalletStorageMock");
    }
}
