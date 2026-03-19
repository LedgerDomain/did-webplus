use crate::Wallet;

/// WalletBasedSigner represents a handle to a specific signing key in a specific wallet at a specific version of specific DID.
/// See Wallet::new_wallet_based_signer for more information.
#[wasm_bindgen::prelude::wasm_bindgen]
#[derive(Clone)]
pub struct WalletBasedSigner(did_webplus_wallet::WalletBasedSigner<Wallet>);

impl std::ops::Deref for WalletBasedSigner {
    type Target = did_webplus_wallet::WalletBasedSigner<Wallet>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<did_webplus_wallet::WalletBasedSigner<Wallet>> for WalletBasedSigner {
    fn from(wallet_based_signer: did_webplus_wallet::WalletBasedSigner<Wallet>) -> Self {
        Self(wallet_based_signer)
    }
}
