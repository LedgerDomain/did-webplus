use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use vjson_store::{AlreadyExistsPolicy, Error, Result, VJSONRecord};

#[derive(Clone)]
pub struct VJSONStorageMock {
    vjson_record_ml: Arc<RwLock<HashMap<selfhash::KERIHash, VJSONRecord>>>,
}

impl VJSONStorageMock {
    pub fn new() -> Self {
        Self {
            vjson_record_ml: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

// TODO: Maybe track if this has been committed or not, so that Drop can determine if
// it would be a rollback (which would mean that it would have to panic because rollback
// is not currently supported).
#[derive(Clone, Debug)]
pub struct VJSONStorageMockTransaction;

impl std::ops::Drop for VJSONStorageMockTransaction {
    fn drop(&mut self) {
        // Nothing to do
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl vjson_store::VJSONStorage for VJSONStorageMock {
    type Transaction<'t> = VJSONStorageMockTransaction;
    async fn begin_transaction<'s, 't: 's, 'u: 't>(
        &self,
        _existing_transaction_o: Option<&'u mut Self::Transaction<'t>>,
    ) -> Result<Self::Transaction<'s>> {
        Ok(VJSONStorageMockTransaction)
    }
    async fn commit_transaction(&self, _transaction: Self::Transaction<'_>) -> Result<()> {
        Ok(())
    }
    async fn rollback_transaction(&self, _transaction: Self::Transaction<'_>) -> Result<()> {
        panic!("Transaction rollback is not supported by VJSONStorageMock");
    }
    async fn add_vjson_str(
        &self,
        _transaction: &mut Self::Transaction<'_>,
        vjson_record: VJSONRecord,
        already_exists_policy: AlreadyExistsPolicy,
    ) -> Result<()> {
        // tracing::trace!(
        //     "VJSONStorageMock attempting to add VJSONRecord with self-hash {}; already_exists_policy: {:?}",
        //     vjson_record.self_hash,
        //     already_exists_policy
        // );
        let mut vjson_record_mg = self.vjson_record_ml.write().unwrap();
        use std::collections::hash_map::Entry;
        match vjson_record_mg.entry(vjson_record.self_hash.clone()) {
            Entry::Occupied(_occupied_entry) => {
                match already_exists_policy {
                    AlreadyExistsPolicy::DoNothing => {
                        // Do nothing
                    }
                    AlreadyExistsPolicy::Fail => {
                        return Err(Error::AlreadyExists(
                            vjson_record.self_hash.to_string().into(),
                        ));
                    }
                }
            }
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(vjson_record);
            }
        }
        // tracing::trace!(
        //     "VJSONStorageMock successfully added VJSONRecord with self-hash {}",
        //     self_hash_str
        // );
        Ok(())
    }
    async fn get_vjson_str(
        &self,
        _transaction: &mut Self::Transaction<'_>,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<VJSONRecord> {
        let vjson_record_mg = self.vjson_record_ml.read().unwrap();
        Ok(vjson_record_mg
            .get(self_hash)
            .ok_or_else(|| Error::NotFound(self_hash.to_string().into()))?
            .clone())
    }
}
