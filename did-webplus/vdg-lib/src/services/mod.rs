#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod did_resolve;

// pub type Result<T, E = anyhow::Error> = ::std::result::Result<T, E>;

// fn internal_error(err: anyhow::Error) -> (axum::http::StatusCode, String) {
//     (
//         axum::http::StatusCode::INTERNAL_SERVER_ERROR,
//         err.to_string(),
//     )
// }
