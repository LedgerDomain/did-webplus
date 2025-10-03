mod error;
mod vjson_record;
mod vjson_storage;
mod vjson_store;

pub use crate::{
    error::{
        error_already_exists, error_internal_error, error_invalid_vjson, error_malformed,
        error_not_found, error_record_corruption, error_storage_error, Error,
    },
    vjson_record::VJSONRecord,
    vjson_storage::VJSONStorage,
    vjson_store::{AlreadyExistsPolicy, VJSONStore},
};
pub type Result<T> = std::result::Result<T, Error>;

/// This function returns the current time in UTC with millisecond precision.  This precision
/// limit is required for interoperability with javascript systems (see
/// <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/now>).
pub fn now_utc_milliseconds() -> time::OffsetDateTime {
    let now_utc = time::OffsetDateTime::now_utc();
    let milliseconds = now_utc.millisecond();
    let now_utc = now_utc.replace_millisecond(milliseconds).unwrap();
    assert_eq!(now_utc.nanosecond() % 1_000_000, 0);
    now_utc
}
