mod error;
mod storage_dyn_t;
mod storage_t;
mod transaction_dyn_t;
mod transaction_t;

pub use crate::{
    error::Error, storage_dyn_t::StorageDynT, storage_t::StorageT,
    transaction_dyn_t::TransactionDynT, transaction_t::TransactionT,
};
pub type Result<T> = std::result::Result<T, Error>;
