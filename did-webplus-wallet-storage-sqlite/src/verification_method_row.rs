pub struct VerificationMethodRow {
    pub rowid: i64,
    pub did_documents_rowid: i64,
    pub key_id_fragment: String,
    pub controller: String,
    pub pub_key: String,
    pub key_purpose_flags: i32,
}
