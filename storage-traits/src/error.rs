use std::borrow::Cow;

#[derive(Clone, Debug)]
pub struct Error(Cow<'static, str>);

impl Error {
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
    pub fn into_inner(self) -> Cow<'static, str> {
        self.0
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl std::error::Error for Error {}

#[cfg(any(feature = "sqlx-postgres", feature = "sqlx-sqlite"))]
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self(Cow::Owned(e.to_string()))
    }
}
