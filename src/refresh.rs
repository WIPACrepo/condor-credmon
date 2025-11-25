use oauth2::RefreshToken;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{coerce_to_int, config as condor_config};
use crate::data::{AccessFile, ClientInfo, RefreshFile, write_tokens_to_file};
use crate::error::CredmonError;

const TOKEN_MINIMUM_EXPIRATION: u64 = 60;

fn is_access_expired(path: &Path, exp_min: u64) -> bool {
    match AccessFile::from_file(path) {
        Ok(x) => {
            // check expiration
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
            let expiration = x.expires_at;
            log::debug!("now: {now}, exp: {expiration}, exp_min: {exp_min}");
            if expiration - exp_min as f64 > now {
                log::info!("  Refresh not needed");
                return false;
            }
        }
        Err(_) => {
            // file is missing, do refresh
            log::info!("  Access token missing!");
        }
    }
    true
}

pub fn should_refresh(refresh_path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let config = condor_config();

    let exp_min = match config.get("CREDMON_OAUTH_TOKEN_MINIMUM") {
        Some(x) => coerce_to_int(x)?,
        None => TOKEN_MINIMUM_EXPIRATION,
    };

    Ok(is_access_expired(&refresh_path.with_extension("use"), exp_min))
}

fn single_refresh(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Checking {}", path.to_str().unwrap());
    let config = condor_config();

    if !should_refresh(path)? {
        return Ok(());
    }
    log::warn!("  Now doing refresh for {}", path.to_str().unwrap());

    let old_refresh_file = RefreshFile::from_file(path)?;

    let provider_name = path.file_stem().unwrap().to_str().unwrap();
    log::info!("  provider(+handle) = {provider_name}");
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

    // 2. Do token refresh
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
                        Err(e) => log::warn!("Error refreshing {}: {e}", path.to_str().unwrap()),
                    };
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    use crate::logging::test_logger;

    #[test]
    fn test_is_access_expired() {
        test_logger();
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();
        let exp = SystemTime::now()
            .checked_add(Duration::from_secs(10))
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let access = AccessFile {
            access_token: "foo".into(),
            token_type: "bearer".into(),
            expires_in: 10,
            expires_at: exp,
            scope: vec![],
        };
        access.write_to_file(path).unwrap();

        assert!(!is_access_expired(path, 5));
        assert!(is_access_expired(path, 20));
    }
}
