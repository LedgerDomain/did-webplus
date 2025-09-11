use std::borrow::Cow;

#[derive(Clone, Debug)]
pub struct Error(std::borrow::Cow<'static, str>);

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
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::borrow::Cow<'static, str>> for Error {
    fn from(s: Cow<'static, str>) -> Self {
        Self(s)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(Cow::Owned(e.to_string()))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self(Cow::Owned(e.to_string()))
    }
}

/// This will construct a formatted Error.
#[macro_export]
macro_rules! error {
    ($msg: literal) => {
        $crate::Error::from($msg)
    };
    ($format_str: literal, $($arg:tt)*) => {
        $crate::Error::from(format!($format_str, $($arg)*))
    };
}

/// This will unconditionally return with the formatted error.
#[macro_export]
macro_rules! bail {
    ($msg: literal) => {
        { return Err($crate::Error::from($msg)); }
    };
    ($format_str: literal, $($arg:tt)*) => {
        { return Err($crate::Error::from(format!($format_str, $($arg)*))); }
    };
}

/// This will return with the formatted error if the condition is not met.
#[macro_export]
macro_rules! require {
    ($condition: expr, $msg: literal) => {
        if !$condition {
            return Err($crate::Error::from($msg));
        }
    };
    ($condition: expr, $format_str: literal, $($arg:tt)*) => {
        if !$condition {
            return Err($crate::Error::from(format!($format_str, $($arg)*)));
        }
    };
}
