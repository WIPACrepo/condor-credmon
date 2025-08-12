use oauth2::basic::BasicTokenType;
use oauth2::ExtraTokenFields;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, OAuth2TokenResponse, RedirectUrl, Scope};
use serde::{Deserialize, Serialize};

use crate::error::CredmonError;

#[derive(Deserialize, Debug, Serialize)]
pub struct CustomTokenExtraFields {
    issued_token_type: String,
}
impl ExtraTokenFields for CustomTokenExtraFields {}

pub fn do_token_exchange() -> Result<oauth2::StandardTokenResponse<CustomTokenExtraFields, BasicTokenType>, Box<dyn std::error::Error>> {
    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Use OpenID Connect Discovery to fetch the provider metadata.
    let provider_metadata = CoreProviderMetadata::discover(
        &IssuerUrl::new("https://keycloak.icecube.wisc.edu/auth/realms/IceCube".to_string())?,
        &http_client,
    )?;
    let token_url = match provider_metadata.token_endpoint() {
        Some(x) => x.to_string(),
        None => return Result::Err(Box::new(CredmonError::DiscoveryError("token url not discovered".into()))),
    };

    let client_id = "test";
    let client_secret = "yVgYMzkG9WeUHKFVIkkM7ooYrf9ov8VF";

    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("http://localhost".to_string())?);

    // 3. Exchange client credentials for an access token
    let token_response = client
        .exchange_client_credentials()?
        .add_scope(Scope::new("offline_access".to_string()))
        .request(&http_client)?; // Or .request_async(&http_client).await? for async

    let subject_token = token_response.access_token().secret();

    // 4. do token exchange
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("audience", client_id),
        ("subject_token", subject_token),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
        ("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token"),
        ("requested_subject", "dschultz"),
    ];

    let result = http_client
        .post(token_url.as_str())
        .basic_auth(client_id, Some(client_secret))
        .form(&params)
        .send()?;

    if result.status().as_u16() >= 400 {
        println!("{}", result.text()?);
        panic!("bad status");
    };
    let body: oauth2::StandardTokenResponse<CustomTokenExtraFields, BasicTokenType> = result.json()?;

    println!("new access token: {:?}", body.access_token().secret());

    match body.refresh_token() {
        Some(_) => Ok(body),
        None => Err(Box::new(CredmonError::MissingRefreshToken(
            "token exchange did not return a refresh token".into(),
        ))),
    }
}
