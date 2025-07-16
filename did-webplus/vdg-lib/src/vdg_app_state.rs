#[derive(Clone)]
pub struct VDGAppState {
    pub did_doc_store: did_webplus_doc_store::DIDDocStore,
    pub http_scheme_override_o: Option<did_webplus_core::HTTPSchemeOverride>,
}
