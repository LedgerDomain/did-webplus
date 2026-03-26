use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub struct WalletRecord(did_webplus_wallet_store::WalletRecord);

#[wasm_bindgen]
impl WalletRecord {
    pub fn wallet_uuid(&self) -> String {
        self.0.wallet_uuid.to_string()
    }
    pub fn created_at(&self) -> String {
        self.0.created_at.to_string()
    }
    pub fn updated_at(&self) -> String {
        self.0.updated_at.to_string()
    }
    pub fn deleted_at(&self) -> Option<String> {
        self.0.deleted_at_o.map(|deleted_at| deleted_at.to_string())
    }
    pub fn wallet_name(&self) -> Option<String> {
        self.0.wallet_name_o.clone()
    }
}

impl From<did_webplus_wallet_store::WalletRecord> for WalletRecord {
    fn from(wallet_record: did_webplus_wallet_store::WalletRecord) -> Self {
        Self(wallet_record)
    }
}

impl From<WalletRecord> for did_webplus_wallet_store::WalletRecord {
    fn from(wallet_record: WalletRecord) -> Self {
        wallet_record.0
    }
}
