use aptos_sdk::rest_client::error::RestError;

/// Aptos client error type.
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Failed to parse HTTP provider URL: {0}")]
    UrlParser(#[from] url::ParseError),

    #[error("Failed: {0}")]
    Rest(#[from] RestError),
}

pub type Result<T> = std::result::Result<T, Error>;