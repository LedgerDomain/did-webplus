mod did_doc_record;
mod did_doc_record_filter;
mod did_doc_storage;
mod did_doc_store;
mod error;

pub use crate::{
    did_doc_record::DIDDocRecord, did_doc_record_filter::DIDDocRecordFilter,
    did_doc_storage::DIDDocStorage, did_doc_store::DIDDocStore, error::Error,
};
pub type Result<T> = std::result::Result<T, Error>;

pub fn parse_did_document(did_document_body: &str) -> Result<did_webplus_core::DIDDocument> {
    let did_document = serde_json::from_str::<did_webplus_core::DIDDocument>(did_document_body)
        .map_err(|_| Error::InvalidDIDDocument("malformed DID document".into()))?;
    did_document.verify_is_canonically_serialized(did_document_body)?;
    Ok(did_document)
}
