use nix::unistd::{Uid, User};
use std::backtrace::Backtrace;
use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use condor_credmon::config::config as condor_config;
use condor_credmon::data::{Args, RefreshFile, compare_scopes, write_tokens_to_file};
use condor_credmon::error::CredmonError;
use condor_credmon::exchange::do_token_exchange;
use condor_credmon::logging::configure_logging;
use condor_credmon::refresh::should_refresh;

fn run() -> Result<(), Box<dyn Error>> {
    let _log_handle = configure_logging(Some("stderr"))?;
    let args = Args::from_env()?;
    let config = condor_config();

    let username = User::from_uid(Uid::current())?
        .ok_or(CredmonError::GenericError("Cannot get username".into()))?
        .name;

    let mut refresh_filename = args.provider.clone();
    if let Some(ref handle) = args.handle {
        refresh_filename += "_";
        refresh_filename += handle;
        log::warn!("Creating token for {username} with provider {} and handle {handle}", args.provider);
    } else {
        log::warn!("Creating token for {username} with provider {} and no handle", args.provider);
    }
    refresh_filename += ".top";

    let cred_dir = config
        .get("SEC_CREDENTIAL_DIRECTORY_OAUTH")
        .ok_or(CredmonError::OAuthDirError("missing SEC_CREDENTIAL_DIRECTORY_OAUTH in config".into()))?
        .as_str()
        .ok_or(CredmonError::OAuthDirError("SEC_CREDENTIAL_DIRECTORY_OAUTH is not a string".into()))?;

    let path = PathBuf::from(cred_dir).join(username.as_str()).join(refresh_filename);

    // check if the token already exists and matches the request
    let create_token = match RefreshFile::from_file(&path) {
        Ok(rf) => {
            if !compare_scopes(args.scopes.as_str(), rf.scopes.as_str()) {
                log::info!("Scopes of existing token do not match. Making new token!");
                true
            } else {
                // check access token and expiration
                should_refresh(&path).unwrap_or(true)
            }
        }
        Err(_) => true,
    };

    if create_token {
        let result = do_token_exchange(&args, username.as_str())?;
        write_tokens_to_file(&path, result)?;
    } else {
        log::warn!("Token already exists, not contacting server");
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            log::info!("Backtrace: {}", Backtrace::force_capture());
            log::error!("Error creating token: {e}");
            ExitCode::FAILURE
        }
    }
}
