use oauth2::TokenResponse;
use std::error::Error;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use condor_credmon::config::config as condor_config;
use condor_credmon::data::{AccessFile, RefreshFile};
use condor_credmon::error::CredmonError;
use condor_credmon::exchange::do_token_exchange;

fn main() -> Result<(), Box<dyn Error>> {
    let config = condor_config();

    let cred_dir = config
        .get("SEC_CREDENTIAL_DIRECTORY_OAUTH")
        .ok_or(CredmonError::OAuthDirError("missing SEC_CREDENTIAL_DIRECTORY_OAUTH in config".into()))?
        .as_str()
        .ok_or(CredmonError::OAuthDirError("SEC_CREDENTIAL_DIRECTORY_OAUTH is not a string".into()))?;

    let username = whoami::username();

    let path = PathBuf::from(cred_dir).join(username);
    let access_path = path.with_extension(".use");

    let result = do_token_exchange().expect("failed exchange");

    // now write the refresh token
    let mut scopes = Vec::new();
    if let Some(s) = result.scopes() {
        //println!("Scopes: {:?}", s);
        scopes.extend(s.iter().map(|x| x.as_str().to_string()));
    }

    RefreshFile {
        refresh_token: result.refresh_token().unwrap().clone().into_secret(),
        scopes: scopes.join(" "),
    }
    .write_to_file(path)?;

    let exp: u64 = result.expires_in().unwrap_or(Duration::from_secs(600)).as_secs();
    let exp_at = SystemTime::now()
        .checked_add(Duration::from_secs(exp))
        .unwrap()
        .duration_since(UNIX_EPOCH)?
        .as_secs_f64();
    AccessFile {
        access_token: result.access_token().clone().into_secret(),
        token_type: result.token_type().as_ref().to_string(),
        expires_in: exp,
        expires_at: exp_at,
        scope: scopes,
    }
    .write_to_file(access_path)?;

    Ok(())
}
