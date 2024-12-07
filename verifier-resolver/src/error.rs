use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid verifier: {0}")]
    InvalidVerifier(Cow<'static, str>),
    #[error("Unsupported verifier: {0}")]
    UnsupportedVerifier(Cow<'static, str>),
}
