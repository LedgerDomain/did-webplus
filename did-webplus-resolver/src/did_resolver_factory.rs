use crate::{DIDResolver, Result};

/// This bit of indirection is used for when loading a particular DIDResolver has nontrivial overhead,
/// e.g. creating a connection to a database, running migrations, making a network request, etc. and
/// thus that loading should be deferred until actually needed.  Implementations of this trait should
/// use std::cell::OnceCell or some similar mechanism to ensure the expensive loading is not done more
/// than necessary.
#[async_trait::async_trait]
pub trait DIDResolverFactory {
    async fn did_resolver(&self) -> Result<&dyn DIDResolver>;
}
