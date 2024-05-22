mod did_doc_record;
mod did_doc_storage;
mod did_doc_store;
mod error;

pub use crate::{
    did_doc_record::DIDDocRecord, did_doc_storage::DIDDocStorage, did_doc_store::DIDDocStore,
    error::Error,
};
pub type Result<T> = std::result::Result<T, Error>;

pub fn parse_did_document(did_document_body: &str) -> Result<did_webplus::DIDDocument> {
    Ok(serde_json::from_str(did_document_body)
        .map_err(|_| did_webplus::Error::Malformed("malformed DID document"))?)
}
