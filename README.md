# condor-credmon
An HTCondor Credmon for creating/refreshing OAuth2 tokens.

Designed to work similarly to the OAuth Credmon, but better.

## Example condor config

Stolen from the [Vault credmon](https://github.com/htcondor/htcondor/blob/main/src/condor_credd/condor_credmon_oauth/examples/config/condor/40-vault-credmon.conf) example.

```
##############################################
# Set up credmon oauth to use the rust credmon
#
DAEMON_LIST = $(DAEMON_LIST) CREDD CREDMON_OAUTH

# MANDATORY for enabling the transfer of credentials from submit host
#   to execute hosts, if encryption is not already enabled.
SEC_DEFAULT_ENCRYPTION = REQUIRED

# Common directories and definition of the various credmon-related daemons
SEC_CREDENTIAL_DIRECTORY_OAUTH = /var/lib/condor/oauth_credentials
TRUST_CREDENTIAL_DIRECTORY = True
CREDMON_OAUTH = /usr/sbin/condor_credmon_rust
CREDMON_OAUTH_LOG = $(LOG)/CredMonOAuthLog
SEC_CREDENTIAL_STORER = /usr/bin/condor_credmod_rust_client

# This is the minimum time in seconds that access tokens must have
#   before they expire when they are fetched by credmon.  It must
#   be set to be less than the expiration time assigned by the token
#   issuer.
CREDMON_OAUTH_TOKEN_MINIMUM=240
# This is the time in seconds between fetching new access tokens.
#   If not set, the default is half of CREDMON_OATH_TOKEN_MINIMUM.
CREDMON_OAUTH_TOKEN_REFRESH=150
# This is the time in seconds that credd will wait after jobs are
#   finished before deleting the user's credential directory.
SEC_CREDENTIAL_SWEEP_DELAY=86400

# Now set up a provider.
OAUTH2_CREDMON_PROVIDER_NAMES = myprovider
# The base path to the issuer, for dynamic discovery.
myprovider_ISSUER = "https://my.issuer.here"
# The client id registered with the issuer.
myprovider_CLIENT_ID = "XXXXXX"
# The client secret is provided in a file that can only be read by root.
myprovider_CLIENT_SECRET_FILE = /etc/condor/.secrets/XXXXXX-client-secret
# Actually tell the STORER which provider this is
myprovider_DEFAULT_OPTIONS = "myprovider"
```
