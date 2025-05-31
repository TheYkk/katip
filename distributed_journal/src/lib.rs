pub mod storage;
pub mod broker;

// Basic error type for now
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Serialization(bincode::Error),
    Deserialization(bincode::Error),
    ChecksumMismatch,
    OffsetNotFound,
    SegmentFull,
    EntryTooLarge,        // Added
    NoActiveSegment,      // Added
    Internal(String),     // Added
    InitializationError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Serialization(e) => write!(f, "Serialization error: {}", e),
            Error::Deserialization(e) => write!(f, "Deserialization error: {}", e),
            Error::ChecksumMismatch => write!(f, "Checksum mismatch"),
            Error::OffsetNotFound => write!(f, "Offset not found"),
            Error::SegmentFull => write!(f, "Segment is full"),
            Error::EntryTooLarge => write!(f, "Entry is too large for segment"),
            Error::NoActiveSegment => write!(f, "No active segment available"),
            Error::Internal(s) => write!(f, "Internal error: {}", s),
            Error::InitializationError(s) => write!(f, "Initialization error: {}", s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Serialization(e) => Some(e),
            Error::Deserialization(e) => Some(e),
            // Other variants don't typically wrap another error.
            _ => None,
        }
    }
}


impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        // Using Box<bincode::Error> can sometimes be problematic for downcasting
        // or if bincode::Error itself is already Boxed.
        // For now, assume ErrorKind::Io for Deserialization is a common case.
        // if matches!(*e, bincode::ErrorKind::Io(_)) {
        //     return Error::Deserialization(e);
        // }
        Error::Serialization(e) // Default to Serialization
    }
}
