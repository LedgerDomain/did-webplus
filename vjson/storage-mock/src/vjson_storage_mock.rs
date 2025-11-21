use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use vjson_store::{AlreadyExistsPolicy, Error, Result, VJSONRecord};

#[derive(Clone)]
pub struct VJSONStorageMock {
    vjson_record_ml: Arc<RwLock<HashMap<mbx::MBHash, VJSONRecord>>>,
}

impl VJSONStorageMock {
    pub fn new() -> Self {
        Self {
            vjson_record_ml: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for VJSONStorageMock {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(Box::new(VJSONStorageMockTransaction))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl vjson_store::VJSONStorage for VJSONStorageMock {
    async fn add_vjson_str(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        vjson_record: VJSONRecord,
        already_exists_policy: AlreadyExistsPolicy,
    ) -> Result<()> {
        tracing::debug!(
            "VJSONStorageMock::add_vjson_str(vjson_record.self_hash: {}, already_exists_policy: {:?})",
            vjson_record.self_hash,
            already_exists_policy
        );
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
        Ok(())
    }
    async fn get_vjson_str(
        &self,
        _transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        self_hash: &mbx::MBHashStr,
    ) -> Result<VJSONRecord> {
        tracing::debug!("VJSONStorageMock::get_vjson_str({})", self_hash);
        let vjson_record_mg = self.vjson_record_ml.read().unwrap();
        let vjson_record = vjson_record_mg
            .get(self_hash)
            .ok_or_else(|| Error::NotFound(self_hash.to_string().into()))?
            .clone();
        Ok(vjson_record)
    }
}

// TODO: Maybe track if this has been committed or not, so that Drop can determine if
// it would be a rollback (which would mean that it would have to panic because rollback
// is not currently supported).
#[derive(Clone, Debug)]
struct VJSONStorageMockTransaction;

impl std::ops::Drop for VJSONStorageMockTransaction {
    fn drop(&mut self) {
        // Nothing to do
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::TransactionDynT for VJSONStorageMockTransaction {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    async fn commit(self: Box<Self>) -> storage_traits::Result<()> {
        Ok(())
    }
    async fn rollback(self: Box<Self>) -> storage_traits::Result<()> {
        panic!("Transaction rollback is not supported by VJSONStorageMock");
    }
}
