use std::path::PathBuf;

/// Everything that can go wrong while planning or running a sandbox.
///
/// The `Policy` variant is deliberately the loudest one: it means Deepsand
/// refused to build a sandbox because doing so would have handed the contained
/// DeepCode instance something it must never have.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox policy violation: {0}")]
    Policy(String),

    #[error("host path rejected: {0}")]
    Path(String),

    #[error("docker is unavailable: {0}")]
    DockerUnavailable(String),

    #[error("docker command failed ({command}): {stderr}")]
    Docker { command: String, stderr: String },

    #[error("project not found: {0}")]
    ProjectNotFound(String),

    #[error("grant not found: {0}")]
    GrantNotFound(String),

    #[error("no sandbox session is running for project {0}")]
    NotRunning(String),

    #[error("a sandbox session is already running for project {0}")]
    AlreadyRunning(String),

    #[error("malformed state file {path}: {message}")]
    StateCorrupt { path: PathBuf, message: String },

    /// The file is there but could not be opened.
    ///
    /// Deliberately distinct from `StateCorrupt`, because the responses have to differ: a
    /// malformed file is moved aside and replaced, while a file that could not be opened
    /// may be perfectly good. Treating the second as the first renamed a valid state
    /// aside and let the app start empty over it.
    #[error("the state file {path} could not be read: {message}")]
    StateUnreadable { path: PathBuf, message: String },

    /// JSON that this build cannot map onto its own shape, which means another version of
    /// Deepsand wrote it.
    ///
    /// Distinct from `StateCorrupt` for the same reason `StateUnreadable` is: the file is
    /// intact and is probably the only copy of what it says, so it must be reported rather
    /// than replaced.
    #[error("the state file {path} was written by a different version of Deepsand: {message}")]
    StateIncompatible { path: PathBuf, message: String },

    #[error("permission broker: {0}")]
    Broker(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, SandboxError>;

impl SandboxError {
    pub fn policy(msg: impl Into<String>) -> Self {
        Self::Policy(msg.into())
    }

    pub fn path(msg: impl Into<String>) -> Self {
        Self::Path(msg.into())
    }
}
