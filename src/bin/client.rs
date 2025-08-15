use nix::unistd::{Uid, User};
use std::backtrace::Backtrace;
use std::error::Error;
use std::path::PathBuf;

use condor_credmon::config::config as condor_config;
use condor_credmon::data::{Args, write_tokens_to_file};
use condor_credmon::error::CredmonError;
use condor_credmon::exchange::do_token_exchange;
use condor_credmon::logging::configure_logging;

fn run() -> Result<(), Box<dyn Error>> {
    let _log_handle = configure_logging(Some("stderr"))?;
    let args = Args::from_env()?;
    let config = condor_config();

    let username = User::from_uid(Uid::current())?
        .ok_or(CredmonError::GenericError("Cannot get username".into()))?
        .name;

    let mut refresh_filename = args.provider.clone();
    if let Some(ref handle) = args.handle {
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

    let path = PathBuf::from(cred_dir).join(username).join(refresh_filename);

    match do_token_exchange(&args) {
        Ok(result) => write_tokens_to_file(&path, result),
        Err(e) => {
            log::warn!("Error getting tokens: {e}");
            Err(e)
        }
    }
}

fn main() {
    match run() {
        Ok(_) => (),
        Err(e) => {
            log::error!("Backtrace: {}", Backtrace::force_capture());
            log::error!("Error creating token: {e}");
        }
    }
}
