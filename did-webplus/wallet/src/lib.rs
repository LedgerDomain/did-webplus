mod error;
mod wallet;

pub use crate::{
    error::Error,
    wallet::{CreateDIDParameters, DeactivateDIDParameters, UpdateDIDParameters, Wallet},
};
pub type Result<T> = std::result::Result<T, Error>;
