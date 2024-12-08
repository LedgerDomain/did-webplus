#[derive(Default)]
pub struct WalletRecordFilter {
    pub wallet_uuid_o: Option<uuid::Uuid>,
    pub wallet_name_o: Option<String>,
}
