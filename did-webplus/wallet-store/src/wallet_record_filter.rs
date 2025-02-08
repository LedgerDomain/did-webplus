use crate::WalletRecord;

#[derive(Default)]
pub struct WalletRecordFilter {
    pub wallet_uuid_o: Option<uuid::Uuid>,
    pub wallet_name_oo: Option<Option<String>>,
}

impl WalletRecordFilter {
    pub fn matches(&self, wallet_record: &WalletRecord) -> bool {
        if let Some(wallet_uuid) = self.wallet_uuid_o.as_ref() {
            if wallet_record.wallet_uuid != *wallet_uuid {
                return false;
            }
        }
        if let Some(wallet_name_o) = self.wallet_name_oo.as_ref() {
            if wallet_record.wallet_name_o != *wallet_name_o {
                return false;
            }
        }
        true
    }
}
