use std::fs;

use oauth2::basic::BasicTokenType;
use oauth2::ExtraTokenFields;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, OAuth2TokenResponse, RedirectUrl, Scope};
use serde::{Deserialize, Serialize};

use crate::config::config as condor_config;
use crate::error::CredmonError;
use crate::data::Args;

#[derive(Deserialize, Debug, Serialize)]
pub struct CustomTokenExtraFields {
    issued_token_type: String,
}
impl ExtraTokenFields for CustomTokenExtraFields {}

pub fn do_token_exchange(args: &Args) -> Result<oauth2::StandardTokenResponse<CustomTokenExtraFields, BasicTokenType>, Box<dyn std::error::Error>> {
    let config = condor_config();

    let provider_name = &args.provider;

    let issuer_key = format!("{provider_name}_ISSUER");
    let issuer_url = IssuerUrl::new(
    config
            .get(&issuer_key)
            .ok_or(CredmonError::IssuerError(format!("missing {issuer_key} in config")))?
            .as_str()
            .ok_or(CredmonError::IssuerError(format!("{issuer_key} is not a string")))?
            .to_string()
    )?;

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

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Use OpenID Connect Discovery to fetch the provider metadata.
    let provider_metadata = CoreProviderMetadata::discover(
        &issuer_url,
        &http_client,
    )?;
    let token_url = match provider_metadata.token_endpoint() {
        Some(x) => x.to_string(),
        None => return Result::Err(Box::new(CredmonError::DiscoveryError("token url not discovered".into()))),
    };

    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        client_id.clone(),
        Some(client_secret.clone()),
    )
    // URL needs to not be empty, so put a dummy URL here
    .set_redirect_uri(RedirectUrl::new("http://localhost".to_string())?);

    // 3. Exchange client credentials for an access token
    let token_response = client
        .exchange_client_credentials()?
        .add_scopes(args.scopes.split(" ").map(|s| Scope::new(s.into())))
        .request(&http_client)?;

    let subject_token = token_response.access_token().secret();

    // 4. do token exchange
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("audience", client_id.as_str()),
        ("subject_token", subject_token),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
        ("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"),
        ("requested_subject", "dschultz"),
    ];

    let result = http_client
        .post(token_url.as_str())
        .basic_auth(client_id.as_str(), Some(client_secret.secret()))
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
