#[cfg(any(feature = "postgres", feature = "sqlite"))]
#[derive(Clone)]
pub struct VDRAppState {
    pub did_doc_store: did_webplus_doc_store::DIDDocStore,
    pub vdr_config: crate::VDRConfig,
}
