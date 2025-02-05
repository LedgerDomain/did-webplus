mod error;
mod vjson_record;
mod vjson_storage;
mod vjson_store;
mod vjson_store_as_resolver;

pub use crate::{
    error::{
        error_already_exists, error_internal_error, error_invalid_vjson, error_malformed,
        error_not_found, error_record_corruption, error_storage_error, Error,
    },
    vjson_record::VJSONRecord,
    vjson_storage::VJSONStorage,
    vjson_store::{AlreadyExistsPolicy, VJSONStore},
    vjson_store_as_resolver::VJSONStoreAsResolver,
};
pub type Result<T> = std::result::Result<T, Error>;
