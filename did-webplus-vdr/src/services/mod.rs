pub mod did;
// pub type Result<T, E = anyhow::Error> = ::std::result::Result<T, E>;

// fn internal_error(err: anyhow::Error) -> (axum::http::StatusCode, String) {
//     (
//         axum::http::StatusCode::INTERNAL_SERVER_ERROR,
//         err.to_string(),
//     )
// }

use sqlx::PgPool;

use crate::config::Config;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    config: Config,
}
