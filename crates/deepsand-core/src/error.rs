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
