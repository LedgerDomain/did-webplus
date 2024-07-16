use crate::PrivKeyUsageType;

#[derive(Default)]
pub struct PrivKeyUsageRecordFilter {
    pub pub_key_o: Option<selfhash::KERIHash>,
    pub usage_type_o: Option<PrivKeyUsageType>,
    pub used_at_or_after_o: Option<time::OffsetDateTime>,
    pub used_at_or_before_o: Option<time::OffsetDateTime>,
}
