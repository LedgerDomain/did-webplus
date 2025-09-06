use crate::{DIDResolverArgs, HTTPSchemeOverrideArgs};
use std::sync::OnceLock;

pub struct DIDResolverFactory {
    did_resolver_args: DIDResolverArgs,
    http_scheme_override_args: HTTPSchemeOverrideArgs,
    did_resolver_bc: OnceLock<Box<dyn did_webplus_resolver::DIDResolver>>,
}

impl DIDResolverFactory {
    pub fn new(
        did_resolver_args: DIDResolverArgs,
        http_scheme_override_args: HTTPSchemeOverrideArgs,
    ) -> Self {
        Self {
            did_resolver_args,
            http_scheme_override_args,
            did_resolver_bc: OnceLock::new(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl did_webplus_resolver::DIDResolverFactory for DIDResolverFactory {
    #[allow(elided_named_lifetimes)]
    async fn did_resolver(
        &self,
    ) -> did_webplus_resolver::Result<&dyn did_webplus_resolver::DIDResolver> {
        if let Some(did_resolver_b) = self.did_resolver_bc.get() {
            return Ok(did_resolver_b.as_ref());
        }

        let http_scheme_override_o =
            Some(self.http_scheme_override_args.http_scheme_override.clone());
        let did_resolver_b = self
            .did_resolver_args
            .clone()
            .get_did_resolver(http_scheme_override_o)
            .await
            .map_err(|e| did_webplus_resolver::Error::GenericError(e.to_string().into()))?;
        if self.did_resolver_bc.set(did_resolver_b).is_err() {
            panic!("programmer error");
        }
        Ok(self.did_resolver_bc.get().unwrap().as_ref())
    }
}
