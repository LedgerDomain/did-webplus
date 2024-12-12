use crate::{Error, Result};

#[async_trait::async_trait]
pub trait VJSONResolver: Send + Sync {
    /// This resolves the given VJSON document.
    async fn resolve_vjson_string(&self, self_hash: &selfhash::KERIHashStr) -> Result<String>;
    /// Convenience method.  This just calls into resolve_vjson_string and then deserializes
    /// the VJSON string into a serde_json::Value.
    async fn resolve_vjson_value(
        &self,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<serde_json::Value> {
        let vjson_string = self.resolve_vjson_string(self_hash).await?;
        let vjson_value: serde_json::Value = serde_json::from_str(&vjson_string)
            .map_err(|e| Error::Malformed(e.to_string().into()))?;
        Ok(vjson_value)
    }
}
