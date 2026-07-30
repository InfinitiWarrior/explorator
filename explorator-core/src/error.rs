use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// A pipeline TOML file could not be parsed.
    PipelineParse(String),
    /// The stage dependency graph contains a cycle or references an unknown stage.
    InvalidPipeline(String),
    /// A referenced plugin identifier has no registered implementation.
    UnknownPlugin(String),
    /// A plugin's required external binary is not installed / not on PATH.
    MissingBinary { plugin: String, binary: String },
    /// A plugin returned an error while executing.
    PluginExecution { plugin: String, message: String },
    /// A stage did not complete within its configured timeout.
    Timeout { stage: String, secs: u64 },
    /// Underlying I/O failure (spawning a process, reading a file, etc).
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PipelineParse(msg) => write!(f, "failed to parse pipeline: {msg}"),
            Error::InvalidPipeline(msg) => write!(f, "invalid pipeline definition: {msg}"),
            Error::UnknownPlugin(name) => write!(f, "unknown plugin: {name}"),
            Error::MissingBinary { plugin, binary } => {
                write!(f, "plugin '{plugin}' requires binary '{binary}' which was not found on PATH")
            }
            Error::PluginExecution { plugin, message } => {
                write!(f, "plugin '{plugin}' failed: {message}")
            }
            Error::Timeout { stage, secs } => {
                write!(f, "stage '{stage}' timed out after {secs}s")
            }
            Error::Io(msg) => write!(f, "io error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::PipelineParse(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
