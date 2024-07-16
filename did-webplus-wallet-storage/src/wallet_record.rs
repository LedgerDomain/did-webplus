pub struct WalletRecord {
    pub wallet_uuid: uuid::Uuid,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
    pub deleted_at_o: Option<time::OffsetDateTime>,
    pub wallet_name_o: Option<String>,
}
