use oauth2::RefreshToken;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{coerce_to_int, config as condor_config};
use crate::data::{AccessFile, ClientInfo, RefreshFile, write_tokens_to_file};
use crate::error::CredmonError;

const TOKEN_MINIMUM_EXPIRATION: u64 = 60;

fn single_refresh(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    log::info!(target: "refresh", "Checking {}", path.to_str().unwrap());

    let config = condor_config();

    let exp_min = match config.get("CREDMON_OAUTH_TOKEN_MINIMUM") {
        Some(x) => coerce_to_int(x)?,
        None => TOKEN_MINIMUM_EXPIRATION,
    };

    let old_refresh_file = RefreshFile::from_file(path)?;
    let access_path = path.with_extension("use");
    match AccessFile::from_file(&access_path) {
        Ok(x) => {
            // check expiration
            let expiration = UNIX_EPOCH + Duration::from_secs_f64(x.expires_at);
            if expiration < SystemTime::now().checked_add(Duration::from_secs(exp_min)).unwrap() {
                log::info!(target: "refresh", "  Refresh not needed");
                return Ok(());
            }
        }
        Err(_) => {
            // file is missing, do refresh
            log::info!(target: "refresh", "  Access token missing!");
        }
    }
    log::warn!(target: "refresh", "  Now doing refresh for {}", path.to_str().unwrap());

    let provider_name = path.file_stem().unwrap().to_str().unwrap();
    log::info!(target: "refresh", "  provider(+handle) = {provider_name}");
    let info = match provider_name.rsplit_once('_') {
        Some((p, _)) => match ClientInfo::new(p, &config) {
            Err(_) => ClientInfo::new(provider_name, &config)?,
            Ok(x) => x,
        },
        None => ClientInfo::new(provider_name, &config)?,
    };

    // 1. Discover the provider metadata (or manually configure if known)
    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let provider_metadata = match CoreProviderMetadata::discover(&info.issuer_url, &http_client) {
        Ok(x) => Ok(x),
        Err(x) => Err(CredmonError::DiscoveryError(x.to_string())),
    }?;

    let client = CoreClient::from_provider_metadata(provider_metadata, info.client_id, Some(info.client_secret))
        .set_redirect_uri(openidconnect::RedirectUrl::new("http://localhost".to_string())?); // Redirect URI is required for client creation, but not strictly used in Client Credentials Flow

    // 3. Exchange client credentials for an access token
    let token_response = client
        .exchange_refresh_token(&RefreshToken::new(old_refresh_file.refresh_token))?
        .request(&http_client)?;

    write_tokens_to_file(path, token_response)
}

pub fn refresh_all_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let config = condor_config();

    let cred_dir = config
        .get("SEC_CREDENTIAL_DIRECTORY_OAUTH")
        .ok_or(CredmonError::OAuthDirError("missing SEC_CREDENTIAL_DIRECTORY_OAUTH in config".into()))?
        .as_str()
        .ok_or(CredmonError::OAuthDirError("SEC_CREDENTIAL_DIRECTORY_OAUTH is not a string".into()))?;

    // iterate over credential directory
    for path in fs::read_dir(cred_dir)? {
        let path = path?;
        if path.file_type()?.is_dir() {
            // this is a user credential dir, so iterate over this
            for path in fs::read_dir(path.path())? {
                let path = path?;
                if path
                    .file_name()
                    .to_str()
                    .ok_or(CredmonError::OAuthDirError("Error decoding filename".into()))?
                    .ends_with(".top")
                {
                    // this is a refresh token, so let's process it
                    let path = path.path();
                    match single_refresh(&path) {
                        Ok(_) => {}
                        Err(e) => log::warn!(target: "refresh", "Error refreshing {}: {e}", path.to_str().unwrap()),
                    };
                }
            }
        }
    }

    Ok(())
}
