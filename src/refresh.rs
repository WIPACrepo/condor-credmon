use oauth2::RefreshToken;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{ClientId, ClientSecret, IssuerUrl, OAuth2TokenResponse};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::config as condor_config;
use crate::data::{AccessFile, RefreshFile};
use crate::error::CredmonError;

fn single_refresh(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = condor_config();

    let old_refresh_file = RefreshFile::from_file(&path)?;
    let access_path = path.with_extension(".use");
    match AccessFile::from_file(&access_path) {
        Ok(x) => {
            // check expiration half-life
            let expiration = UNIX_EPOCH + Duration::from_secs_f64(x.expires_at);
            if expiration < SystemTime::now().checked_sub(Duration::from_secs(x.expires_in / 2)).unwrap() {
                return Ok(());
            }
        }
        Err(_) => {
            // file is missing, do refresh
        }
    }

    let provider_name = path.file_stem().unwrap().to_str().unwrap();

    let client_id_key = format!("{provider_name}_CLIENT_ID");
    let client_id = ClientId::new(
        config
            .get(&client_id_key)
            .ok_or(CredmonError::OAuthDirError(format!("missing {client_id_key} in config")))?
            .as_str()
            .ok_or(CredmonError::OAuthDirError(format!("{client_id_key} is not a string")))?
            .to_string(),
    );

    let client_secret_key = format!("{provider_name}_CLIENT_SECRET_FILE");
    let client_secret_file = config
        .get(&client_secret_key)
        .ok_or(CredmonError::OAuthDirError(format!("missing {client_secret_key} in config")))?
        .as_str()
        .ok_or(CredmonError::OAuthDirError(format!("{client_secret_key} is not a string")))?;
    let client_secret = ClientSecret::new(fs::read_to_string(client_secret_file)?);

    // 1. Discover the provider metadata (or manually configure if known)
    let issuer_url = IssuerUrl::new("https://keycloak.icecube.wisc.edu/auth/realms/IceCube".to_string())?;

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let provider_metadata = CoreProviderMetadata::discover(&issuer_url, &http_client)?;

    let client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
        .set_redirect_uri(openidconnect::RedirectUrl::new("http://localhost".to_string())?); // Redirect URI is required for client creation, but not strictly used in Client Credentials Flow

    // 3. Exchange client credentials for an access token
    let token_response = client
        .exchange_refresh_token(&RefreshToken::new(old_refresh_file.refresh_token))?
        .request(&http_client)?;

    // 4. Access the token
    let access_token = token_response.access_token().secret();
    //println!("Access Token: {access_token}");
    let refresh_token = token_response.refresh_token().expect("no refresh token").secret();
    //println!("Refresh Token: {refresh_token}");

    let mut scopes = Vec::new();
    if let Some(s) = token_response.scopes() {
        //println!("Scopes: {:?}", s);
        scopes.extend(s.iter().map(|x| x.as_str().to_string()));
    }

    // now write the refresh and access tokens
    RefreshFile {
        refresh_token: refresh_token.clone(),
        scopes: scopes.join(" "),
    }
    .write_to_file(path)?;

    let exp: u64 = token_response.expires_in().unwrap_or(Duration::from_secs(600)).as_secs();
    let exp_at = SystemTime::now()
        .checked_add(Duration::from_secs(exp))
        .unwrap()
        .duration_since(UNIX_EPOCH)?
        .as_secs_f64();
    AccessFile {
        access_token: access_token.clone(),
        token_type: token_response.token_type().as_ref().to_string(),
        expires_in: exp,
        expires_at: exp_at,
        scope: scopes,
    }
    .write_to_file(access_path)?;

    Ok(())
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
                    single_refresh(path.path())?;
                }
            }
        }
    }

    Ok(())
}
