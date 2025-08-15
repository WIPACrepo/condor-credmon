use std::error::Error;
use std::fmt;

#[derive(Debug)] // Required for the `Error` trait
pub enum CredmonError {
    ArgumentError(String),
    DiscoveryError(String),
    ClientCredenialsError(String),
    MissingRefreshToken(String),
    OAuthDirError(String),
    IssuerError(String),
    ConfigError(String),
    GenericError(String),
}

impl Error for CredmonError {}

impl fmt::Display for CredmonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CredmonError::ArgumentError(details) => write!(f, "ArgumentError: {details}"),
            CredmonError::DiscoveryError(details) => write!(f, "DiscoveryError: {details}"),
            CredmonError::ClientCredenialsError(details) => write!(f, "ClientCredenialsError: {details}"),
            CredmonError::MissingRefreshToken(details) => write!(f, "MissingRefreshToken: {details}"),
            CredmonError::OAuthDirError(details) => write!(f, "OAuthDirError: {details}"),
            CredmonError::IssuerError(details) => write!(f, "IssuerError: {details}"),
            CredmonError::ConfigError(details) => write!(f, "ConfigError: {details}"),
            CredmonError::GenericError(details) => write!(f, "GenericError: {details}"),
        }
    }
}
