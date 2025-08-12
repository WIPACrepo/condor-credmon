use std::error::Error;
use std::fmt;

#[derive(Debug)] // Required for the `Error` trait
pub enum CredmonError {
    DiscoveryError(String),
    ClientCredenialsError(String),
    MissingRefreshToken(String),
    OAuthDirError(String),
}

impl Error for CredmonError {}

impl fmt::Display for CredmonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CredmonError::DiscoveryError(details) => write!(f, "DiscoveryError: {}", details),
            CredmonError::ClientCredenialsError(details) => write!(f, "ClientCredenialsError: {}", details),
            CredmonError::MissingRefreshToken(details) => write!(f, "MissingRefreshToken: {}", details),
            CredmonError::OAuthDirError(details) => write!(f, "OAuthDirError:{}", details),
        }
    }
}
