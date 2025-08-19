use oauth2::ExtraTokenFields;
use oauth2::basic::BasicTokenType;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{OAuth2TokenResponse, RedirectUrl};
use serde::{Deserialize, Serialize};

use crate::config::config as condor_config;
use crate::data::{Args, ClientInfo};
use crate::error::CredmonError;

#[derive(Deserialize, Debug, Serialize)]
pub struct CustomTokenExtraFields {
    issued_token_type: String,
}
impl ExtraTokenFields for CustomTokenExtraFields {}

pub fn do_token_exchange(
    args: &Args,
    username: &str,
) -> Result<oauth2::StandardTokenResponse<CustomTokenExtraFields, BasicTokenType>, Box<dyn std::error::Error>> {
    let config = condor_config();
    log::info!("Getting tokens");
    log::info!("  provider = {}", args.provider);

    let info = ClientInfo::new(args.provider.as_str(), &config)?;

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Use OpenID Connect Discovery to fetch the provider metadata.
    let provider_metadata = match CoreProviderMetadata::discover(&info.issuer_url, &http_client) {
        Ok(x) => Ok(x),
        Err(x) => Err(CredmonError::DiscoveryError(x.to_string())),
    }?;

    let token_url = match provider_metadata.token_endpoint() {
        Some(x) => x.to_string(),
        None => return Result::Err(Box::new(CredmonError::DiscoveryError("token url not discovered".into()))),
    };

    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        info.client_id.clone(),
        Some(info.client_secret.clone()),
    )
    // URL needs to not be empty, so put a dummy URL here
    .set_redirect_uri(RedirectUrl::new("http://localhost".to_string())?);

    // 3. Exchange client credentials for an access token
    let token_response = client.exchange_client_credentials()?.request(&http_client)?;

    let subject_token = token_response.access_token().secret();

    // 4. do token exchange
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("audience", info.client_id.as_str()),
        ("subject_token", subject_token),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
        ("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"),
        ("requested_subject", username),
        ("scope", &args.scopes),
    ];

    let result = http_client
        .post(token_url.as_str())
        .basic_auth(info.client_id.as_str(), Some(info.client_secret.secret()))
        .form(&params)
        .send()?;

    if result.status().as_u16() >= 400 {
        println!("{}", result.text()?);
        panic!("bad status");
    };
    let body: oauth2::StandardTokenResponse<CustomTokenExtraFields, BasicTokenType> = result.json()?;

    match body.refresh_token() {
        Some(_) => Ok(body),
        None => Err(Box::new(CredmonError::MissingRefreshToken(
            "token exchange did not return a refresh token".into(),
        ))),
    }
}
