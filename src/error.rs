#[derive(Debug)]
pub enum LogFsError {
    NotFound { path: super::Path },
    Internal { message: String },
    Io(std::io::Error),
    Conversion(bincode::Error),
    Tainted,
}

impl LogFsError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self::Internal {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for LogFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogFsError::Internal { message } => {
                write!(f, "{}", message)
            }
            LogFsError::Io(err) => err.fmt(f),
            LogFsError::Conversion(err) => err.fmt(f),
            LogFsError::NotFound { path } => {
                write!(f, "File not found: {:?}", path)
            }
            LogFsError::Tainted => write!(
                f,
                "The database is tainted and can not be used for writes until re-initialization."
            ),
        }
    }
}

impl std::error::Error for LogFsError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self {
            LogFsError::Internal { .. } => None,
            LogFsError::Io(err) => Some(err),
            LogFsError::Conversion(err) => Some(err),
            LogFsError::NotFound { path: _ } => None,
            LogFsError::Tainted => None,
        }
    }
}

impl From<std::io::Error> for LogFsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<bincode::Error> for LogFsError {
    fn from(err: bincode::Error) -> Self {
        Self::Conversion(err)
    }
}
