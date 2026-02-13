mod error;
mod wallet;
#[cfg(feature = "ssi")]
mod wallet_based_signer;

#[cfg(feature = "ssi")]
pub use crate::wallet_based_signer::WalletBasedSigner;
pub use crate::{
    error::Error,
    wallet::{CreateDIDParameters, DeactivateDIDParameters, UpdateDIDParameters, Wallet},
};
pub type Result<T> = std::result::Result<T, Error>;
