use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Mutable per-vector VDR simulation state for the test-vector HTTP server.
///
/// Tracks how many leading `did-documents.jsonl` lines are currently published
/// ([`Self::served_did_document_count`]) and how many GETs that body has received
/// ([`Self::jsonl_request_count`]). Defaults to serving the full microledger;
/// [`Self::reset`] restores that default and zeroes the request counter.
#[derive(Debug)]
pub struct TestVectorServerVectorRuntime {
    served_did_document_count: AtomicU32,
    jsonl_request_count: AtomicU64,
    default_served_did_document_count: u32,
}

impl TestVectorServerVectorRuntime {
    /// Create runtime state that initially serves all `default_served_did_document_count` lines.
    pub fn new(default_served_did_document_count: u32) -> Self {
        Self {
            served_did_document_count: AtomicU32::new(default_served_did_document_count),
            jsonl_request_count: AtomicU64::new(0),
            default_served_did_document_count,
        }
    }

    /// How many leading jsonl lines the VDR currently serves.
    pub fn served_did_document_count(&self) -> u32 {
        self.served_did_document_count.load(Ordering::SeqCst)
    }

    /// Set how many leading jsonl lines the VDR serves.
    pub fn set_served_did_document_count(&self, count: u32) {
        self.served_did_document_count
            .store(count, Ordering::SeqCst);
    }

    /// Number of GETs for this vector's `did-documents.jsonl` since last reset.
    pub fn jsonl_request_count(&self) -> u64 {
        self.jsonl_request_count.load(Ordering::SeqCst)
    }

    /// Increment the jsonl GET counter; returns the new value.
    pub fn increment_jsonl_request_count(&self) -> u64 {
        self.jsonl_request_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Restore full serve-count and zero the jsonl request counter.
    pub fn reset(&self) {
        self.served_did_document_count
            .store(self.default_served_did_document_count, Ordering::SeqCst);
        self.jsonl_request_count.store(0, Ordering::SeqCst);
    }

    /// Full-document serve-count restored by [`Self::reset`].
    pub fn default_served_did_document_count(&self) -> u32 {
        self.default_served_did_document_count
    }
}
