use log::warn;
use std::error::Error;
use std::path::PathBuf;

use condor_credmon::config::config as condor_config;
use condor_credmon::data::{Args, write_tokens_to_file};
use condor_credmon::error::CredmonError;
use condor_credmon::exchange::do_token_exchange;

fn main() -> Result<(), Box<dyn Error>> {
    stderrlog::new().module(module_path!()).init().unwrap();

    let config = condor_config();

    let args = Args::from_env()?;

    let mut refresh_filename = args.provider.clone();
    if let Some(ref handle) = args.handle {
        refresh_filename += handle;
    }

    let cred_dir = config
        .get("SEC_CREDENTIAL_DIRECTORY_OAUTH")
        .ok_or(CredmonError::OAuthDirError("missing SEC_CREDENTIAL_DIRECTORY_OAUTH in config".into()))?
        .as_str()
        .ok_or(CredmonError::OAuthDirError("SEC_CREDENTIAL_DIRECTORY_OAUTH is not a string".into()))?;

    let username = whoami::username();

    let path = PathBuf::from(cred_dir).join(username).join(refresh_filename);

    match do_token_exchange(&args) {
        Ok(result) => write_tokens_to_file(&path, result),
        Err(e) => {
            warn!("Error getting tokens: {e}");
            Err(e)
        }
    }
}
