use oauth2::basic::BasicTokenType;
use oauth2::{ClientId, ClientSecret, ExtraTokenFields, TokenResponse};
use openidconnect::IssuerUrl;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::error::CredmonError;

#[derive(Serialize, Deserialize)]
pub struct RefreshFile {
    pub refresh_token: String,
    pub scopes: String,
}

impl RefreshFile {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let data = serde_json::from_reader(reader)?;
        Ok(data)
    }

    pub fn write_to_file<P: AsRef<Path>>(self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(&self)?;
        let mut file = File::create(path)?;
        file.write_all(json_string.as_bytes())?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct AccessFile {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub expires_at: f64,
    pub scope: Vec<String>,
}

impl AccessFile {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let data = serde_json::from_reader(reader)?;
        Ok(data)
    }

    pub fn write_to_file<P: AsRef<Path>>(self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(&self)?;
        let mut file = File::create(path)?;
        file.write_all(json_string.as_bytes())?;
        Ok(())
    }
}

pub fn write_tokens_to_file<EF: ExtraTokenFields>(
    refresh_path: &Path,
    result: oauth2::StandardTokenResponse<EF, BasicTokenType>,
) -> Result<(), Box<dyn std::error::Error>> {
    let access_path = refresh_path.with_extension("use");

    let parent_path = access_path.parent().unwrap();
    if !parent_path.exists() {
        fs::create_dir_all(parent_path)?;
    }

    // now write the refresh token
    log::info!("Writing refresh token at {}", refresh_path.to_str().unwrap());
    let mut scopes = Vec::new();
    if let Some(s) = result.scopes() {
        //println!("Scopes: {:?}", s);
        scopes.extend(s.iter().map(|x| x.as_str().to_string()));
    }

    RefreshFile {
        refresh_token: result.refresh_token().unwrap().clone().into_secret(),
        scopes: scopes.join(" "),
    }
    .write_to_file(refresh_path)?;

    log::info!("Writing access token at {}", access_path.to_str().unwrap());
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

/// Client storer arguments
pub struct Args {
    pub provider: String,
    pub scopes: String,
    pub handle: Option<String>,
}

impl Args {
    pub fn from_env() -> Result<Self, Box<dyn Error>> {
        let argv: Vec<String> = env::args().collect();
        Self::from_env_impl(argv)
    }

    fn from_env_impl(argv: Vec<String>) -> Result<Self, Box<dyn Error>> {
        if argv.len() < 2 {
            return Err(Box::new(CredmonError::ArgumentError("need to specify scopes and options (provider)".into())));
        }

        let mut args = HashMap::new();
        for entry in argv[1].split('&') {
            if let Some((key, val)) = entry.split_once('=') {
                args.insert(key.to_string(), val.to_string());
            }
        }

        let provider = match args.get("options") {
            Some(opts) => opts.to_owned(),
            None => {
                return Err(Box::new(CredmonError::ArgumentError("need to specify provider in options".into())));
            }
        };

        let scopes = match args.get("scopes") {
            Some(scopes) => scopes.replace(",", " "),
            None => String::new(),
        };

        let handle = args.get("handle").map(|h| h.to_owned());

        Ok(Self { provider, scopes, handle })
    }
}

pub struct ClientInfo {
    pub issuer_url: IssuerUrl,
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
}

impl ClientInfo {
    pub fn new(provider_name: &str, config: &Config) -> Result<Self, Box<dyn Error>> {
        let issuer_key = format!("{provider_name}_ISSUER");
        let issuer_url = IssuerUrl::new(
            config
                .get(&issuer_key)
                .ok_or(CredmonError::IssuerError(format!("missing {issuer_key} in config")))?
                .as_str()
                .ok_or(CredmonError::IssuerError(format!("{issuer_key} is not a string")))?
                .to_string(),
        )?;
        log::info!(target: "refresh", "  issuer = {issuer_url}");

        let client_id_key = format!("{provider_name}_CLIENT_ID");
        let client_id = ClientId::new(
            config
                .get(&client_id_key)
                .ok_or(CredmonError::OAuthDirError(format!("missing {client_id_key} in config")))?
                .as_str()
                .ok_or(CredmonError::OAuthDirError(format!("{client_id_key} is not a string")))?
                .to_string(),
        );
        log::info!(target: "refresh", "  client_id = {}", client_id.as_str());

        let client_secret_key = format!("{provider_name}_CLIENT_SECRET_FILE");
        let client_secret_file = config
            .get(&client_secret_key)
            .ok_or(CredmonError::OAuthDirError(format!("missing {client_secret_key} in config")))?
            .as_str()
            .ok_or(CredmonError::OAuthDirError(format!("{client_secret_key} is not a string")))?;
        let client_secret = ClientSecret::new(fs::read_to_string(client_secret_file)?);

        Ok(Self {
            issuer_url,
            client_id,
            client_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::logging::test_logger;

    #[test]
    fn test_args_none() {
        test_logger();
        let fake_args = vec![];
        let ret = Args::from_env_impl(fake_args);
        assert!(ret.err().unwrap().to_string().contains("ArgumentError"));
    }

    #[test]
    fn test_args_no_options() {
        test_logger();
        let fake_args = vec![String::from("exec"), String::from("scopes=foo")];
        let ret = Args::from_env_impl(fake_args);
        let s = ret.err().unwrap().to_string();
        assert!(s.contains("specify provider"));
    }

    #[test]
    fn test_args_no_scopes() {
        test_logger();
        let fake_args = vec![String::from("exec"), String::from("options=provider")];
        let ret = Args::from_env_impl(fake_args).ok().unwrap();
        assert_eq!(ret.provider, "provider");
        assert_eq!(ret.scopes, "");
        assert_eq!(ret.handle, None);
    }

    #[test]
    fn test_args_scopes() {
        test_logger();
        let fake_args = vec![String::from("exec"), String::from("scopes=foo,bar&options=provider")];
        let ret = Args::from_env_impl(fake_args).ok().unwrap();
        assert_eq!(ret.provider, "provider");
        assert_eq!(ret.scopes, "foo bar");
        assert_eq!(ret.handle, None);
    }

    #[test]
    fn test_args_handle() {
        test_logger();
        let fake_args = vec![String::from("exec"), String::from("scopes=foo,bar&options=provider&handle=baz")];
        let ret = Args::from_env_impl(fake_args).ok().unwrap();
        assert_eq!(ret.provider, "provider");
        assert_eq!(ret.scopes, "foo bar");
        assert_eq!(ret.handle, Some("baz".into()));
    }

    #[test]
    fn test_client_info() {
        test_logger();
        let mut config: serde_json::Map<String, Value> = serde_json::Map::new();
        config.insert("test_ISSUER".into(), "http://foo".into());
        config.insert("test_CLIENT_ID".into(), "client".into());
        let mut file = NamedTempFile::new().ok().unwrap();
        write!(file, "secret").ok().unwrap();
        config.insert("test_CLIENT_SECRET_FILE".into(), file.path().to_str().into());

        let ret = ClientInfo::new("test", &config);
        match ret {
            Err(e) => {
                panic!("should not fail: {e}")
            }
            Ok(x) => {
                assert_eq!(x.issuer_url.as_str(), "http://foo");
                assert_eq!(x.client_id.as_str(), "client");
                assert_eq!(x.client_secret.secret().as_str(), "secret");
            }
        }
    }
}
