#[derive(Debug)]
pub enum LogFsError {
    ReadOnly,
    NotFound {
        path: super::Path,
    },
    Internal {
        message: String,
        backtrace: backtrace::Backtrace,
    },
    Io {
        error: std::io::Error,
        backtrace: backtrace::Backtrace,
    },
    Conversion(SerializationError),
    Tainted,
    WriterClosed,
}

impl LogFsError {
    pub(crate) fn new_internal(msg: impl Into<String>) -> Self {
        Self::Internal {
            message: msg.into(),
            backtrace: backtrace::Backtrace::new(),
        }
    }

    pub(crate) fn into_io(self) -> std::io::Error {
        match self {
            LogFsError::Io { error, .. } => error,
            other => std::io::Error::other(other),
        }
    }
}

impl std::fmt::Display for LogFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogFsError::Internal { message, .. } => {
                write!(f, "{}", message)
            }
            LogFsError::Io { error, .. } => error.fmt(f),
            LogFsError::Conversion(err) => err.fmt(f),
            LogFsError::NotFound { path } => {
                write!(f, "File not found: {:?}", path)
            }
            LogFsError::Tainted => write!(
                f,
                "The database is tainted and can not be used for writes until re-initialization."
            ),
            LogFsError::WriterClosed => write!(f, "Log was closed for writes"),
            LogFsError::ReadOnly => write!(f, "Could not insert: log is read-only"),
        }
    }
}

impl std::error::Error for LogFsError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self {
            LogFsError::Internal { .. } => None,
            LogFsError::Io { error, .. } => Some(error),
            LogFsError::Conversion(err) => Some(err),
            LogFsError::NotFound { path: _ } => None,
            LogFsError::Tainted => None,
            LogFsError::WriterClosed => None,
            LogFsError::ReadOnly => None,
        }
    }
}

impl From<std::io::Error> for LogFsError {
    #[track_caller]
    fn from(error: std::io::Error) -> Self {
        Self::Io {
            error,
            backtrace: backtrace::Backtrace::new(),
        }
    }
}

#[derive(Debug)]
pub enum SerializationError {
    Encode(bincode::error::EncodeError),
    Decode(bincode::error::DecodeError),
}

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(error) => error.fmt(f),
            Self::Decode(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SerializationError {}

impl From<bincode::error::EncodeError> for LogFsError {
    fn from(error: bincode::error::EncodeError) -> Self {
        Self::Conversion(SerializationError::Encode(error))
    }
}

impl From<bincode::error::DecodeError> for LogFsError {
    fn from(error: bincode::error::DecodeError) -> Self {
        Self::Conversion(SerializationError::Decode(error))
    }
}
