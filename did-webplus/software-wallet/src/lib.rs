mod software_wallet;

pub use software_wallet::SoftwareWallet;

// TEMP HACK
lazy_static::lazy_static! {
    /// Building a reqwest::Client is *incredibly* slow, so we use a global instance and then clone
    /// it per use, as the documentation indicates.
    pub(crate) static ref REQWEST_CLIENT: reqwest::Client = reqwest::Client::new();
}
