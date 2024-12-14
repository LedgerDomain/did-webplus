use crate::{DIDResolverArgs, DIDResolverFactory, DIDWebplusVerifierResolver, HTTPSchemeArgs};

/// Arguments for specifying how to resolve a public key (aka verifier) from a string.
// TODO: This always supports did:key and did:webplus -- should it be configurable?
#[derive(clap::Args, Debug)]
pub struct VerifierResolverArgs {
    #[command(flatten)]
    pub did_resolver_args: DIDResolverArgs,
    #[command(flatten)]
    pub http_scheme_args: HTTPSchemeArgs,
}

impl VerifierResolverArgs {
    pub fn get_verifier_resolver_map(self) -> verifier_resolver::VerifierResolverMap {
        verifier_resolver::VerifierResolverMap::new()
            .with("did:key:", Box::new(did_key::DIDKeyVerifierResolver))
            .with(
                "did:webplus:",
                Box::new(DIDWebplusVerifierResolver {
                    did_resolver_factory_b: Box::new(DIDResolverFactory::new(
                        self.did_resolver_args,
                        self.http_scheme_args,
                    )),
                }),
            )
    }
}
