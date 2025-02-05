#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod did;
// pub type Result<T, E = anyhow::Error> = ::std::result::Result<T, E>;

// fn internal_error(err: anyhow::Error) -> (axum::http::StatusCode, String) {
//     (
//         axum::http::StatusCode::INTERNAL_SERVER_ERROR,
//         err.to_string(),
//     )
// }

#[cfg(any(feature = "postgres", feature = "sqlite"))]
#[derive(Clone)]
struct VDRState {
    did_doc_store: did_webplus_doc_store::DIDDocStore,
    vdr_config: crate::VDRConfig,
}
