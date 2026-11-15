use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io { context: String, source: io::Error },
    Parse(String),
    Unsupported(String),
    Permission(String),
    Usage(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn parse(msg: impl Into<String>) -> Self {
        Error::Parse(msg.into())
    }

    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported(msg.into())
    }

    pub fn permission(msg: impl Into<String>) -> Self {
        Error::Permission(msg.into())
    }

    pub fn usage(msg: impl Into<String>) -> Self {
        Error::Usage(msg.into())
    }

    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    pub fn is_permission(&self) -> bool {
        match self {
            Error::Permission(_) => true,
            Error::Io { source, .. } => {
                source.kind() == io::ErrorKind::PermissionDenied
                    || source.raw_os_error() == Some(libc::EPERM)
            }
            _ => false,
        }
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::Io { source, .. } if source.kind() == io::ErrorKind::NotFound)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Parse(m) => write!(f, "parse error: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Permission(m) => write!(f, "permission denied: {m}"),
            Error::Usage(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub trait IoContext<T> {
    fn context(self, context: impl Into<String>) -> Result<T>;
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| Error::io(context, e))
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| Error::io(f(), e))
    }
}
