//! Azure error types.

use thiserror::Error;

/// Result type for Azure operations.
pub type Result<T> = std::result::Result<T, AzureError>;

/// Azure service errors.
#[derive(Debug, Error)]
pub enum AzureError {
    /// Service not enabled.
    #[error("Service '{0}' is not enabled. Enable the feature flag in Cargo.toml")]
    ServiceNotEnabled(&'static str),

    /// Service not configured.
    #[error("Service '{0}' is not configured. Call enable_{0}() on AzureConfig")]
    ServiceNotConfigured(&'static str),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Authentication error.
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Storage account not specified.
    #[error("Azure storage account not specified")]
    StorageAccountNotSpecified,

    /// Service error.
    #[error("Azure service error: {0}")]
    Service(String),

    /// An Azure service answered with an unsuccessful HTTP status.
    #[error("Azure service error: {message}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Description including the method, path and status.
        message: String,
    },

    /// Network error.
    #[error("Network error: {0}")]
    Network(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl AzureError {
    /// Create a service not enabled error.
    pub fn not_enabled(service: &'static str) -> Self {
        Self::ServiceNotEnabled(service)
    }

    /// Create a service not configured error.
    pub fn not_configured(service: &'static str) -> Self {
        Self::ServiceNotConfigured(service)
    }

    /// The HTTP status of an [`AzureError::Http`] error.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Whether retrying the operation may succeed: transport failures, request
    /// timeouts, throttling and server-side errors (408, 429, 500, 502, 503, 504).
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(_) => true,
            Self::Http { status, .. } => matches!(status, 408 | 429 | 500 | 502 | 503 | 504),
            _ => false,
        }
    }
}
