/// Because of a bug in an early version of SQLite, PRIMARY KEY doesn't imply NOT NULL.
/// https://www.sqlite.org/lang_createtable.html
/// Thus we have to have a hacky, separate version of did_webplus_doc_store::DIDDocRecord
/// in which the self_hash field is Option<_>
#[derive(Debug)]
pub struct DIDDocumentRowSQLite {
    pub self_hash: Option<String>,
    pub did: String,
    pub version_id: i64,
    pub valid_from: time::OffsetDateTime,
    pub did_documents_jsonl_octet_length: i64,
    pub did_document_jcs: String,
}

impl TryFrom<DIDDocumentRowSQLite> for did_webplus_doc_store::DIDDocRecord {
    type Error = did_webplus_doc_store::Error;
    fn try_from(
        did_doc_record_sqlite: DIDDocumentRowSQLite,
    ) -> did_webplus_doc_store::Result<Self> {
        Ok(did_webplus_doc_store::DIDDocRecord {
            self_hash: did_doc_record_sqlite.self_hash.ok_or(
                did_webplus_doc_store::Error::StorageError(
                    "self_hash column was expected to be non-NULL".into(),
                ),
            )?,
            did: did_doc_record_sqlite.did,
            version_id: did_doc_record_sqlite.version_id,
            valid_from: did_doc_record_sqlite.valid_from,
            did_documents_jsonl_octet_length: did_doc_record_sqlite
                .did_documents_jsonl_octet_length,
            did_document_jcs: did_doc_record_sqlite.did_document_jcs,
        })
    }
}
