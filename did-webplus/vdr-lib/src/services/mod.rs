pub mod did;
// pub type Result<T, E = anyhow::Error> = ::std::result::Result<T, E>;

// fn internal_error(err: anyhow::Error) -> (axum::http::StatusCode, String) {
//     (
//         axum::http::StatusCode::INTERNAL_SERVER_ERROR,
//         err.to_string(),
//     )
// }

use did_webplus_doc_storage_postgres::DIDDocStoragePostgres;
use did_webplus_doc_store::DIDDocStore;

use crate::VDRConfig;

#[derive(Clone)]
struct VDRState {
    did_doc_store: DIDDocStore<DIDDocStoragePostgres>,
    vdr_config: VDRConfig,
}
