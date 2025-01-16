// use std::{
//     collections::HashMap,
//     sync::{Arc, RwLock},
// };

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct Hippo {
//     pub name: String,
//     pub age: i64,
// }

// #[derive(Clone)]
// pub struct HippoStorageState {
//     next_rowid: usize,
//     hippo_m: HashMap<usize, Hippo>,
// }

// impl HippoStorageState {
//     pub fn new() -> Self {
//         Self {
//             next_rowid: 0,
//             hippo_m: HashMap::new(),
//         }
//     }
// }

// #[derive(Clone)]
// pub struct HippoStorage {
//     state_l: Arc<RwLock<HippoStorageState>>,
// }

// impl HippoStorage {
//     pub fn new() -> Self {
//         let state = HippoStorageState::new();
//         let state_l = Arc::new(RwLock::new(state));
//         Self { state_l }
//     }
// }

// #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
// impl storage_traits::StorageT for HippoStorage {
//     type Transaction<'t> = HippoTransaction;
//     /// Begin a transaction.
//     async fn begin_transaction(&self) -> storage_traits::Result<Self::Transaction<'_>> {
//         let transaction_state = self.state_l.read().unwrap().clone();
//         Ok(HippoTransaction {
//             backup_state_l: self.state_l.clone(),
//             transaction_state,
//         })
//     }
// }

// pub struct HippoTransaction {
//     backup_state_l: Arc<RwLock<HippoStorageState>>,
//     transaction_state_l: Arc<RwLock<HippoStorageState>>,
// }

// impl std::ops::Drop for HippoTransaction {
//     fn drop(&mut self) {
//         // Nothing to do actually.
//     }
// }

// #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
// impl storage_traits::TransactionT<'_> for HippoTransaction {
//     async fn commit(self) -> storage_traits::Result<()> {
//         *self.backup_state_l.write().unwrap() = self.transaction_state;
//         Ok(())
//     }
//     async fn rollback(self) -> storage_traits::Result<()> {
//         Ok(())
//     }
// }
