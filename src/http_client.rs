use reqwest::{Certificate, Client, ClientBuilder};
use std::time::Duration;
use thiserror::Error;

pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Error, Debug)]
pub enum HttpClientError {
    #[error("Failed to parse certificate: {0}")]
    Certificate(#[from] reqwest::Error),
    #[error("Failed to build HTTP client: {0}")]
    Build(String),
}

/// Creates a standard reqwest ClientBuilder with cookies enabled, standard timeouts,
/// and webpki root certificates.
pub fn default_client_builder() -> ClientBuilder {
    Client::builder()
        .cookie_store(true)
        .timeout(DEFAULT_HTTP_TIMEOUT)
}

/// Builds a production-ready HTTP Client with webpki trust roots.
pub fn create_default_client() -> Result<Client, HttpClientError> {
    default_client_builder()
        .build()
        .map_err(|e| HttpClientError::Build(e.to_string()))
}

/// Builds an HTTP Client with an additional custom root certificate (e.g. for testing or private CAs).
pub fn create_client_with_root_cert(cert_der: &[u8]) -> Result<Client, HttpClientError> {
    let cert = Certificate::from_der(cert_der)?;
    default_client_builder()
        .add_root_certificate(cert)
        .build()
        .map_err(|e| HttpClientError::Build(e.to_string()))
}
