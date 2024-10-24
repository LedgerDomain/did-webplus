use uuid::Uuid;

pub struct WalletRow {
    pub rowid: i64,
    pub wallet_uuid: Uuid,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
    pub deleted_at_o: Option<time::OffsetDateTime>,
    pub description_o: Option<String>,
}
