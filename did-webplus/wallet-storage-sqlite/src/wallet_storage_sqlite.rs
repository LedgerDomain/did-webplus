use crate::{DIDDocumentRowSQLite, PrivKeyRow, PrivKeyUsageInsert, PrivKeyUsageSelect};
use did_webplus_core::{
    DIDDocument, DIDKeyResourceFullyQualifiedStr, DIDStr, KeyPurposeFlags, now_utc_milliseconds,
};
use did_webplus_doc_store::{DIDDocRecord, DIDDocRecordFilter, DIDDocStorage};
use did_webplus_wallet_store::{
    Error, LocallyControlledVerificationMethodFilter, PrivKeyRecord, PrivKeyRecordFilter,
    PrivKeyUsageRecord, PrivKeyUsageRecordFilter, Result, VerificationMethodRecord, WalletRecord,
    WalletRecordFilter, WalletStorage, WalletStorageCtx,
};
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Clone)]
pub struct WalletStorageSQLite {
    sqlite_pool: SqlitePool,
}

impl WalletStorageSQLite {
    pub async fn open_and_run_migrations(sqlite_pool: SqlitePool) -> Result<Self> {
        sqlx::migrate!().run(&sqlite_pool).await.map_err(|err| {
            Error::StorageError(
                format!(
                    "Failed to run SQLite database migrations; error was: {}",
                    err
                )
                .into(),
            )
        })?;
        Ok(Self { sqlite_pool })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl DIDDocStorage for WalletStorageSQLite {
    async fn add_did_document(
        &self,
        mut transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &DIDDocument,
        did_document_jcs: &str,
    ) -> did_webplus_doc_store::Result<()> {
        use selfhash::HashRefT;
        assert!(
            !did_document.self_hash.is_placeholder(),
            "programmer error: self_hash is expected to be present on a valid DID document"
        );
        let did_str = did_document.did.as_str();
        let version_id = did_document.version_id as i64;
        let valid_from = did_document.valid_from;
        let self_hash_str = did_document.self_hash.as_str();
        // TODO: Figure out if ON CONFLICT DO NOTHING is appropriate here -- not sure how returning the rowid
        // would interact with that.
        let query = sqlx::query!(
            r#"
                INSERT INTO did_document_records(did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs)
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    COALESCE(
                        (
                            SELECT did_documents_jsonl_octet_length
                            FROM did_document_records
                            WHERE did = $1
                            ORDER BY version_id DESC
                            LIMIT 1
                        ),
                        0
                    ) + OCTET_LENGTH($5) + 1,
                    $5
                )
                RETURNING rowid
            "#,
            did_str,
            version_id,
            valid_from,
            self_hash_str,
            did_document_jcs,
        );
        let did_document_records_rowid = if let Some(transaction) = transaction_o.as_mut() {
            query
                .fetch_one(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
                .rowid
        } else {
            query.fetch_one(&self.sqlite_pool).await?.rowid
        };

        // Also ingest the verification methods into the verification_methods table
        for verification_method in did_document
            .public_key_material
            .verification_method_v
            .iter()
        {
            let key_id_fragment_str = verification_method.id.fragment();
            let controller = verification_method.controller.as_str();
            let pub_key = mbx::MBPubKey::try_from(&verification_method.public_key_jwk)?.to_string();
            let key_purpose_flags = did_document
                .public_key_material
                .key_purpose_flags_for_key_id_fragment(verification_method.id.fragment());
            let key_purpose_flags_integer = key_purpose_flags.integer_value() as i32;
            let query = sqlx::query!(
                r#"
                    INSERT INTO verification_methods(did_document_records_rowid, key_id_fragment, controller, pub_key, key_purpose_flags)
                    VALUES ($1, $2, $3, $4, $5)
                "#,
                did_document_records_rowid,
                key_id_fragment_str,
                controller,
                pub_key,
                key_purpose_flags_integer,
            );
            if let Some(transaction) = transaction_o.as_mut() {
                query
                    .execute(
                        transaction
                            .as_any_mut()
                            .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                            .unwrap()
                            .as_mut(),
                    )
                    .await?;
            } else {
                query.execute(&self.sqlite_pool).await?;
            }
        }
        Ok(())
    }
    async fn add_did_documents(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _did_document_jcs_v: &[&str],
        _did_document_v: &[DIDDocument],
    ) -> did_webplus_doc_store::Result<()> {
        todo!();
    }
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        self_hash: &mbx::MBHashStr,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let self_hash_str = self_hash.as_str();
        let query = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE did = $1 AND self_hash = $2
            "#,
            did_str,
            self_hash_str,
        );
        let did_doc_record_o = if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.sqlite_pool).await?
        }
        .map(|did_document_row_sqlite| did_document_row_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        version_id: u32,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let version_id = version_id as i64;
        let query = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE did = $1 AND version_id = $2
            "#,
            did_str,
            version_id,
        );
        let did_doc_record_o = if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.sqlite_pool).await?
        }
        .map(|did_document_row_sqlite| did_document_row_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_latest_known_did_doc_record(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> did_webplus_doc_store::Result<Option<DIDDocRecord>> {
        let did_str = did.as_str();
        let query = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE did = $1
                ORDER BY version_id DESC
                LIMIT 1
            "#,
            did_str,
        );
        let did_doc_record_o = if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.sqlite_pool).await?
        }
        .map(|did_document_row_sqlite| did_document_row_sqlite.try_into())
        .transpose()?;
        Ok(did_doc_record_o)
    }
    async fn get_did_doc_records(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_doc_record_filter: &DIDDocRecordFilter,
    ) -> did_webplus_doc_store::Result<Vec<DIDDocRecord>> {
        let filter_on_did = did_doc_record_filter.did_o.is_some();
        let filter_on_self_hash = did_doc_record_filter.self_hash_o.is_some();
        let filter_on_version_id = did_doc_record_filter.version_id_o.is_some();
        // TODO: SQL-based filtering on valid_at
        // let filter_on_valid_at = did_doc_record_filter.valid_at_o.is_some();
        let query = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE (NOT $1 OR did = $2) AND
                      (NOT $3 OR self_hash = $4) AND
                      (NOT $5 OR version_id = $6)
            "#,
            filter_on_did,
            did_doc_record_filter.did_o,
            filter_on_self_hash,
            did_doc_record_filter.self_hash_o,
            filter_on_version_id,
            did_doc_record_filter.version_id_o,
        );
        let did_doc_record_v = if let Some(transaction) = transaction_o {
            query
                .fetch_all(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_all(&self.sqlite_pool).await?
        }
        .into_iter()
        .map(|did_doc_record_sqlite| did_doc_record_sqlite.try_into())
        .collect::<did_webplus_doc_store::Result<Vec<_>>>()?;
        Ok(did_doc_record_v)
    }
    async fn get_did_doc_records_for_did_documents_jsonl_range(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        range_begin_inclusive_o: Option<u64>,
        range_end_exclusive_o: Option<u64>,
    ) -> did_webplus_doc_store::Result<Vec<DIDDocRecord>> {
        let range_begin_inclusive = range_begin_inclusive_o.map(|x| x as i64).unwrap_or(0);
        let range_end_exclusive = range_end_exclusive_o.map(|x| x as i64).unwrap_or(i64::MAX);

        if range_begin_inclusive >= range_end_exclusive {
            // If the range is empty (or invalid), return an empty vector.
            return Ok(Vec::new());
        }

        let did_str = did.as_str();
        let query = sqlx::query_as!(
            DIDDocumentRowSQLite,
            r#"
                SELECT did, version_id, valid_from, self_hash, did_documents_jsonl_octet_length, did_document_jcs
                FROM did_document_records
                WHERE did = $1 AND
                      $2 < did_documents_jsonl_octet_length AND
                      did_documents_jsonl_octet_length - (OCTET_LENGTH(did_document_jcs) + 1) < $3
                ORDER BY version_id ASC
            "#,
            did_str,
            range_begin_inclusive,
            range_end_exclusive,
        );
        let did_document_row_sqlite_v = if let Some(transaction) = transaction_o {
            query
                .fetch_all(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_all(&self.sqlite_pool).await?
        };
        let did_doc_record_v = did_document_row_sqlite_v
            .into_iter()
            .map(|did_document_row_sqlite| did_document_row_sqlite.try_into())
            .collect::<did_webplus_doc_store::Result<Vec<_>>>()?;
        Ok(did_doc_record_v)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for WalletStorageSQLite {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(Box::new(self.sqlite_pool.begin().await?))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl WalletStorage for WalletStorageSQLite {
    async fn add_wallet(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_record: WalletRecord,
    ) -> Result<WalletStorageCtx> {
        let wallet_uuid_string = wallet_record.wallet_uuid.as_hyphenated();
        let query = sqlx::query!(
            r#"
                INSERT INTO wallets(wallet_uuid, created_at, updated_at, deleted_at_o, wallet_name_o)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING rowid
            "#,
            wallet_uuid_string,
            wallet_record.created_at,
            wallet_record.updated_at,
            wallet_record.deleted_at_o,
            wallet_record.wallet_name_o,
        );
        let query_result = if let Some(transaction) = transaction_o {
            query
                .fetch_one(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_one(&self.sqlite_pool).await?
        };
        Ok(WalletStorageCtx {
            wallets_rowid: query_result.rowid,
        })
    }
    async fn get_wallet(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_uuid: &uuid::Uuid,
    ) -> Result<Option<(WalletStorageCtx, WalletRecord)>> {
        let wallet_uuid_string = wallet_uuid.as_hyphenated();
        let query = sqlx::query!(
            r#"
                SELECT rowid, wallet_uuid, created_at, updated_at, deleted_at_o, wallet_name_o
                FROM wallets
                WHERE wallet_uuid = $1
            "#,
            wallet_uuid_string,
        );
        let query_result_o = if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.sqlite_pool).await?
        };
        if let Some(query_result) = query_result_o {
            let wallet_storage_ctx = WalletStorageCtx {
                wallets_rowid: query_result.rowid,
            };
            let wallet_record = WalletRecord {
                wallet_uuid: uuid::Uuid::parse_str(query_result.wallet_uuid.as_str()).map_err(
                    |e| {
                        Error::RecordCorruption(
                            format!(
                                "invalid wallet_uuid {}; error was: {}",
                                query_result.wallet_uuid, e
                            )
                            .into(),
                        )
                    },
                )?,
                created_at: query_result.created_at,
                updated_at: query_result.updated_at,
                deleted_at_o: query_result.deleted_at_o,
                wallet_name_o: query_result.wallet_name_o,
            };
            Ok(Some((wallet_storage_ctx, wallet_record)))
        } else {
            Ok(None)
        }
    }
    async fn get_wallets(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        wallet_record_filter: &WalletRecordFilter,
    ) -> Result<Vec<(WalletStorageCtx, WalletRecord)>> {
        let filter_on_wallet_uuid = wallet_record_filter.wallet_uuid_o.is_some();
        let wallet_uuid_string_o = wallet_record_filter
            .wallet_uuid_o
            .as_ref()
            .map(|wallet_uuid| wallet_uuid.as_hyphenated());
        let filter_on_wallet_name_o = wallet_record_filter.wallet_name_oo.is_some();
        let wallet_name_o =
            if let Some(wallet_name_o) = wallet_record_filter.wallet_name_oo.as_ref() {
                wallet_name_o.as_deref()
            } else {
                None
            };
        let query = sqlx::query!(
            r#"
                SELECT rowid, wallet_uuid, created_at, updated_at, deleted_at_o, wallet_name_o
                FROM wallets
                WHERE 
                    (NOT $1 OR wallet_uuid = $2) AND
                    (NOT $3 OR wallet_name_o = $4)
            "#,
            filter_on_wallet_uuid,
            wallet_uuid_string_o,
            filter_on_wallet_name_o,
            wallet_name_o,
        );
        if let Some(transaction) = transaction_o {
            query
                .fetch_all(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_all(&self.sqlite_pool).await?
        }
        .into_iter()
        .map(|query_result| -> Result<(WalletStorageCtx, WalletRecord)> {
            let wallet_storage_ctx = WalletStorageCtx {
                wallets_rowid: query_result.rowid,
            };
            let wallet_record = WalletRecord {
                wallet_uuid: uuid::Uuid::try_parse(query_result.wallet_uuid.as_str()).map_err(
                    |e| {
                        Error::RecordCorruption(
                            format!(
                                "Invalid UUID in database: {}; error was: {}",
                                query_result.wallet_uuid, e
                            )
                            .into(),
                        )
                    },
                )?,
                created_at: query_result.created_at,
                updated_at: query_result.updated_at,
                deleted_at_o: query_result.deleted_at_o,
                wallet_name_o: query_result.wallet_name_o,
            };
            Ok((wallet_storage_ctx, wallet_record))
        })
        .collect::<Result<Vec<_>>>()
    }

    async fn add_priv_key(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_record: PrivKeyRecord,
    ) -> Result<()> {
        let priv_key_row = PrivKeyRow::try_from_priv_key_record(ctx, priv_key_record)?;
        let query = sqlx::query!(
            r#"
                INSERT INTO priv_keys(
                    wallets_rowid,
                    pub_key,
                    hashed_pub_key,
                    key_type,
                    did_restriction_o,
                    key_purpose_restriction_o,
                    created_at,
                    last_used_at_o,
                    max_usage_count_o,
                    usage_count,
                    deleted_at_o,
                    priv_key_format_o,
                    priv_key_bytes_o,
                    comment_o
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
            priv_key_row.wallets_rowid,
            priv_key_row.pub_key,
            priv_key_row.hashed_pub_key,
            priv_key_row.key_type,
            priv_key_row.did_restriction_o,
            priv_key_row.key_purpose_restriction_o,
            priv_key_row.created_at,
            priv_key_row.last_used_at_o,
            priv_key_row.max_usage_count_o,
            priv_key_row.usage_count,
            priv_key_row.deleted_at_o,
            priv_key_row.priv_key_format_o,
            priv_key_row.priv_key_bytes_o,
            priv_key_row.comment_o,
        );
        if let Some(transaction) = transaction_o {
            query
                .execute(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?;
        } else {
            query.execute(&self.sqlite_pool).await?;
        }
        Ok(())
    }
    async fn delete_priv_key(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        pub_key: &mbx::MBPubKeyStr,
    ) -> Result<()> {
        let deleted_at_o = Some(now_utc_milliseconds());
        let pub_key_str = pub_key.as_str();
        // This will only update if the priv key is not already deleted.
        let query = sqlx::query!(
            r#"
                UPDATE priv_keys
                SET deleted_at_o = $1, priv_key_format_o = NULL, priv_key_bytes_o = NULL
                WHERE wallets_rowid = $2 AND pub_key = $3 AND deleted_at_o IS NULL
            "#,
            deleted_at_o,
            ctx.wallets_rowid,
            pub_key_str,
        );
        if let Some(transaction) = transaction_o {
            query
                .execute(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?;
        } else {
            query.execute(&self.sqlite_pool).await?;
        }
        Ok(())
    }
    async fn get_priv_key(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        pub_key: &mbx::MBPubKeyStr,
    ) -> Result<Option<PrivKeyRecord>> {
        let pub_key_str = pub_key.as_str();
        let query = sqlx::query_as!(
            PrivKeyRow,
            r#"
                SELECT 
                    wallets_rowid,
                    pub_key,
                    hashed_pub_key,
                    key_type,
                    did_restriction_o,
                    key_purpose_restriction_o,
                    created_at,
                    last_used_at_o,
                    max_usage_count_o,
                    usage_count,
                    deleted_at_o,
                    priv_key_format_o,
                    priv_key_bytes_o,
                    comment_o
                FROM priv_keys
                WHERE wallets_rowid = $1 AND pub_key = $2
            "#,
            ctx.wallets_rowid,
            pub_key_str,
        );
        if let Some(transaction) = transaction_o {
            query
                .fetch_optional(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_optional(&self.sqlite_pool).await?
        }
        .map(PrivKeyRow::try_into_priv_key_record)
        .transpose()
    }
    async fn get_priv_keys(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_record_filter: &PrivKeyRecordFilter,
    ) -> Result<Vec<PrivKeyRecord>> {
        tracing::trace!(?priv_key_record_filter, "getting priv keys");

        let filter_on_pub_key = priv_key_record_filter.pub_key_o.is_some();
        let pub_key_str_o = priv_key_record_filter
            .pub_key_o
            .as_ref()
            .map(|pub_key| pub_key.as_str());

        let filter_on_hashed_pub_key = priv_key_record_filter.hashed_pub_key_o.is_some();
        let hashed_pub_key_str_o = priv_key_record_filter
            .hashed_pub_key_o
            .as_ref()
            .map(|hashed_pub_key| hashed_pub_key.as_str());

        let filter_on_did = priv_key_record_filter.did_o.is_some();
        let did_str_o = priv_key_record_filter
            .did_o
            .as_ref()
            .map(|did| did.as_str());

        let filter_on_key_purpose_flags = priv_key_record_filter.key_purpose_flags_o.is_some();
        let key_purpose_flags_integer_o = priv_key_record_filter
            .key_purpose_flags_o
            .map(|key_purpose_flags| key_purpose_flags.integer_value() as i64);

        let filter_on_is_not_deleted = priv_key_record_filter.is_not_deleted_o.is_some();

        tracing::trace!(?filter_on_key_purpose_flags, ?key_purpose_flags_integer_o);

        let query = sqlx::query_as!(
            PrivKeyRow,
            r#"
                SELECT 
                    wallets_rowid,
                    pub_key,
                    hashed_pub_key,
                    key_type,
                    did_restriction_o,
                    key_purpose_restriction_o,
                    created_at,
                    last_used_at_o,
                    max_usage_count_o,
                    usage_count,
                    deleted_at_o,
                    priv_key_format_o,
                    priv_key_bytes_o,
                    comment_o
                FROM priv_keys
                WHERE wallets_rowid = $1
                    AND (NOT $2 OR pub_key = $3)
                    AND (NOT $4 OR hashed_pub_key = $5)
                    AND (NOT $6 OR did_restriction_o IS NULL OR did_restriction_o = $7)
                    AND (NOT $8 OR key_purpose_restriction_o IS NULL OR (key_purpose_restriction_o & $9) != 0)
                    AND (NOT $10 OR (deleted_at_o IS NULL) = $11)
            "#,
            ctx.wallets_rowid,
            filter_on_pub_key,
            pub_key_str_o,
            filter_on_hashed_pub_key,
            hashed_pub_key_str_o,
            filter_on_did,
            did_str_o,
            filter_on_key_purpose_flags,
            key_purpose_flags_integer_o,
            filter_on_is_not_deleted,
            priv_key_record_filter.is_not_deleted_o,
        );
        let priv_key_row_v = if let Some(transaction) = transaction_o {
            query
                .fetch_all(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_all(&self.sqlite_pool).await?
        };
        let priv_key_record_v = priv_key_row_v
            .into_iter()
            .map(|row| row.try_into_priv_key_record())
            .collect::<Result<Vec<_>>>()?;
        Ok(priv_key_record_v)
    }

    async fn add_priv_key_usage(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record: &PrivKeyUsageRecord,
    ) -> Result<()> {
        let priv_key_usage_insert =
            PrivKeyUsageInsert::try_from_priv_key_usage_record(ctx, priv_key_usage_record)?;
        let query = sqlx::query!(
            r#"
                INSERT INTO priv_key_usages(
                    wallets_rowid,
                    priv_keys_rowid,
                    used_at,
                    usage_type,
                    usage_spec_o,
                    verification_method_o,
                    key_purpose_o
                )
                VALUES ($1, (SELECT rowid FROM priv_keys WHERE wallets_rowid = $1 AND pub_key = $2), $3, $4, $5, $6, $7);

                UPDATE priv_keys
                SET last_used_at_o = $8, usage_count = usage_count+1
                WHERE wallets_rowid = $9 AND pub_key = $10
            "#,
            priv_key_usage_insert.wallets_rowid,
            priv_key_usage_insert.pub_key,
            priv_key_usage_insert.used_at,
            priv_key_usage_insert.usage_type,
            priv_key_usage_insert.usage_spec_o,
            priv_key_usage_insert.verification_method_o,
            priv_key_usage_insert.key_purpose_o,
            // NOTE: The redundancy here seems to be necessary due to an apparent limitation of sqlx.
            priv_key_usage_insert.used_at,
            priv_key_usage_insert.wallets_rowid,
            priv_key_usage_insert.pub_key,
        );
        if let Some(transaction) = transaction_o {
            query
                .execute(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?;
        } else {
            query.execute(&self.sqlite_pool).await?;
        }
        Ok(())
    }
    async fn get_priv_key_usages(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        priv_key_usage_record_filter: &PrivKeyUsageRecordFilter,
    ) -> Result<Vec<PrivKeyUsageRecord>> {
        let filter_on_pub_key = priv_key_usage_record_filter.pub_key_o.is_some();
        let pub_key_str_o = priv_key_usage_record_filter
            .pub_key_o
            .as_ref()
            .map(|pub_key| pub_key.as_str());

        let filter_on_usage_type = priv_key_usage_record_filter.usage_type_o.is_some();
        let usage_type_str_o = priv_key_usage_record_filter
            .usage_type_o
            .as_ref()
            .map(|usage_type| usage_type.as_str());

        let filter_on_used_at_or_after = priv_key_usage_record_filter.used_at_or_after_o.is_some();

        let filter_on_used_at_or_before =
            priv_key_usage_record_filter.used_at_or_before_o.is_some();

        let query = sqlx::query_as!(
            PrivKeyUsageSelect,
            r#"
                SELECT 
                    priv_key_usages.rowid,
                    priv_key_usages.wallets_rowid,
                    priv_keys.pub_key,
                    priv_keys.hashed_pub_key,
                    priv_key_usages.used_at,
                    priv_key_usages.usage_type,
                    priv_key_usages.usage_spec_o,
                    priv_key_usages.verification_method_o,
                    priv_key_usages.key_purpose_o
                FROM priv_key_usages
                INNER JOIN priv_keys
                    ON priv_key_usages.priv_keys_rowid = priv_keys.rowid
                WHERE priv_key_usages.wallets_rowid = $1
                    AND (NOT $2 OR priv_keys.pub_key = $3)
                    AND (NOT $4 OR priv_key_usages.usage_type = $5)
                    AND (NOT $6 OR priv_key_usages.used_at >= $7)
                    AND (NOT $8 OR priv_key_usages.used_at <= $9)
            "#,
            ctx.wallets_rowid,
            filter_on_pub_key,
            pub_key_str_o,
            filter_on_usage_type,
            usage_type_str_o,
            filter_on_used_at_or_after,
            priv_key_usage_record_filter.used_at_or_after_o,
            filter_on_used_at_or_before,
            priv_key_usage_record_filter.used_at_or_before_o,
        );
        let priv_key_usage_row_v = if let Some(transaction) = transaction_o {
            query
                .fetch_all(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_all(&self.sqlite_pool).await?
        };
        let mut priv_key_usage_record_v = Vec::with_capacity(priv_key_usage_row_v.len());
        for priv_key_usage_row in priv_key_usage_row_v.into_iter() {
            let priv_key_usage_record = priv_key_usage_row.try_into_priv_key_usage_record(ctx)?;
            priv_key_usage_record_v.push(priv_key_usage_record);
        }
        Ok(priv_key_usage_record_v)
    }

    async fn get_verification_method(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        _ctx: &WalletStorageCtx,
        _did_key_resource_fully_qualified: &DIDKeyResourceFullyQualifiedStr,
    ) -> Result<VerificationMethodRecord> {
        unimplemented!();
    }

    async fn get_locally_controlled_verification_methods(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        ctx: &WalletStorageCtx,
        locally_controlled_verification_method_filter: &LocallyControlledVerificationMethodFilter,
    ) -> Result<Vec<(VerificationMethodRecord, PrivKeyRecord)>> {
        let filter_on_did = locally_controlled_verification_method_filter
            .did_o
            .is_some();
        let did_o = locally_controlled_verification_method_filter
            .did_o
            .as_ref()
            .map(|did| did.as_str());

        let filter_on_version_id = locally_controlled_verification_method_filter
            .version_id_o
            .is_some();

        let filter_on_key_purpose = locally_controlled_verification_method_filter
            .key_purpose_o
            .is_some();

        let key_purpose_integer_o = locally_controlled_verification_method_filter
            .key_purpose_o
            .map(|key_purpose| key_purpose.as_key_purpose_flags().integer_value() as i64);

        let query = sqlx::query!(
            r#"
                SELECT
                    verification_methods.did_document_records_rowid,
                    verification_methods.key_id_fragment,
                    verification_methods.controller,
                    verification_methods.key_purpose_flags,
                    did_document_records.did,
                    did_document_records.self_hash,
                    did_document_records.version_id,
                    priv_keys.pub_key,
                    priv_keys.hashed_pub_key,
                    priv_keys.key_type,
                    priv_keys.did_restriction_o,
                    priv_keys.key_purpose_restriction_o,
                    priv_keys.created_at,
                    priv_keys.last_used_at_o,
                    priv_keys.max_usage_count_o,
                    priv_keys.usage_count,
                    priv_keys.deleted_at_o,
                    priv_keys.priv_key_format_o,
                    priv_keys.priv_key_bytes_o,
                    priv_keys.comment_o
                FROM verification_methods
                INNER JOIN did_document_records
                    ON verification_methods.did_document_records_rowid = did_document_records.rowid
                INNER JOIN priv_keys
                    ON verification_methods.pub_key = priv_keys.pub_key
                WHERE
                    priv_keys.wallets_rowid = $1
                    AND priv_keys.deleted_at_o IS NULL
                    AND (NOT $2 OR did_document_records.did = $3)
                    AND (NOT $4 OR did_document_records.version_id = $5)
                    AND (NOT $6 OR (verification_methods.key_purpose_flags & $7 != 0))
            "#,
            ctx.wallets_rowid,
            filter_on_did,
            did_o,
            filter_on_version_id,
            locally_controlled_verification_method_filter.version_id_o,
            filter_on_key_purpose,
            key_purpose_integer_o,
        );
        let query_result_v = if let Some(transaction) = transaction_o {
            query
                .fetch_all(
                    transaction
                        .as_any_mut()
                        .downcast_mut::<sqlx::Transaction<'static, sqlx::Sqlite>>()
                        .unwrap()
                        .as_mut(),
                )
                .await?
        } else {
            query.fetch_all(&self.sqlite_pool).await?
        };

        let mut locally_controlled_verification_method_v = Vec::with_capacity(query_result_v.len());
        for query_result in query_result_v.into_iter() {
            let did = DIDStr::new_ref(query_result.did.as_str()).map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "invalid did_document_records.did value {}; error was: {}",
                        query_result.did, e
                    )
                    .into(),
                )
            })?;
            let self_hash =
                mbx::MBHashStr::new_ref(query_result.self_hash.as_str()).map_err(|e| {
                    Error::RecordCorruption(
                        format!(
                            "invalid did_document_records.self_hash value {}; error was: {}",
                            query_result.self_hash, e
                        )
                        .into(),
                    )
                })?;
            let version_id = u32::try_from(query_result.version_id).map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "invalid did_document_records.version_id value {}; error was: {}",
                        query_result.version_id, e
                    )
                    .into(),
                )
            })?;
            let did_key_resource_fully_qualified = did
                .with_queries(self_hash, version_id)
                .with_fragment(query_result.key_id_fragment.as_str());

            let key_purpose_flags = KeyPurposeFlags::try_from(
                u8::try_from(query_result.key_purpose_flags).map_err(|e| {
                    Error::RecordCorruption(
                        format!(
                            "invalid verification_methods.key_purpose_flags value {}; error was: {}",
                            query_result.key_purpose_flags, e,
                        )
                        .into(),
                    )
                })?,
            )
            .map_err(|e| {
                Error::RecordCorruption(
                    format!(
                        "invalid verification_methods.key_purpose_flags value {}; error was: {}",
                        query_result.key_purpose_flags, e,
                    )
                    .into(),
                )
            })?;

            let priv_key_row = PrivKeyRow {
                wallets_rowid: ctx.wallets_rowid,
                pub_key: query_result.pub_key,
                hashed_pub_key: query_result.hashed_pub_key,
                key_type: query_result.key_type,
                did_restriction_o: query_result.did_restriction_o,
                key_purpose_restriction_o: query_result.key_purpose_restriction_o,
                created_at: query_result.created_at,
                last_used_at_o: query_result.last_used_at_o,
                max_usage_count_o: query_result.max_usage_count_o,
                usage_count: query_result.usage_count,
                deleted_at_o: query_result.deleted_at_o,
                priv_key_format_o: query_result.priv_key_format_o,
                priv_key_bytes_o: query_result.priv_key_bytes_o,
                comment_o: query_result.comment_o,
            };
            let priv_key_record = priv_key_row.try_into_priv_key_record()?;

            let verification_method_record = VerificationMethodRecord {
                did_key_resource_fully_qualified,
                key_purpose_flags,
                pub_key: priv_key_record.pub_key.clone(),
            };
            locally_controlled_verification_method_v
                .push((verification_method_record, priv_key_record));
        }
        Ok(locally_controlled_verification_method_v)
    }
    fn as_did_doc_storage(&self) -> &dyn did_webplus_doc_store::DIDDocStorage {
        self
    }
    fn as_did_doc_storage_a(self: Arc<Self>) -> Arc<dyn did_webplus_doc_store::DIDDocStorage> {
        self.clone()
    }
}
