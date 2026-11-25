# Client Management

The OpenID frontend offers the `satosa-oidc-frontend-clients` command for its client
management.

The following commands are offered:
    - `create`: Create a client
    - `delete`: Delete a client
    - `get`: Get a client's info
    - `list`: List all clients
    - `modify`: Modify an existing client

The db_uri can either be provided through the command line arg `--db-uri`
or via the env var `SATOSA_OIDC_FRONTEND_DB_URI`.


## Creating new clients

To add a new client run the command:

```
env SATOSA_OIDC_FRONTEND_DB_URI={db_uri} \
satosa-oidc-frontend-clients create {client_id} {client_secret}
```

The available parameters are:
- `--redirect-uris`: One or more comma separated redirect_uris
- `--response-types`: One or more comma separated response types
- `--grant-types-supported`: One or more comma separated grant types e.g. --grant-types-supported authorization_code,refresh_token
- `--allowed-scopes`: One or more comma separated allowed scopes e.g. --allowed-scopes openid,profile
- `--claims-always-access-token`: One or more comma separated claims to be added to the access token e.g. --claims-always-access-token first_name,birth_date
- `--claims-always-id-token`: One or more comma separated claims to be added to the id token e.g. --claims-always-id-token first_name,birth_date
- `--claims-always-userinfo`: One or more comma separated claims to be added to the userinfo token e.g. --claims-always-userinfo first_name,birth_date
- `--revoke-refresh-on-issue`: Revoke refresh tokens after they have been used
- `--pkce-essential`: Make use of PKCE is mandatory
- `--claims-by-scope-access-token`: Add claims by scope to the access token, e.g. --claims-by-scope-access-token true
- `--claims-by-scope-id-token`: Add claims by scope to the id token, e.g. --claims-by-scope-id-token true
- `--claims-by-scope-userinfo`: Add claims by scope to the userinfo, e.g. --claims-by-scope-userinfo false
- `-p` or `--client-param`: Set another client param e.g. -p post_logout_redirect_uri=http://some/path. Use this argument to define any metadata not available using the other params


## Getting a client's information

To get a client's metadata run the command:

`env SATOSA_OIDC_FRONTEND_DB_URI={db_uri} satosa-oidc-frontend-clients get {client_id}`


## Listing all existing clients

To get all the available clients run the command:

`env SATOSA_OIDC_FRONTEND_DB_URI={db_uri} satosa-oidc-frontend-clients list`


## Deleting a client

To delete a client run the command:

`env SATOSA_OIDC_FRONTEND_DB_URI={db_uri} satosa-oidc-frontend-clients delete {client_id}`


## Modifying a client's metadata

To modify an existing clients metadata run the command:

```
env SATOSA_OIDC_FRONTEND_DB_URI={db_uri} \
satosa-oidc-frontend-clients modify {client_id} {client_secret}
```

The available parameters are:
- `--add-redirect-uri`: Add a redirect_uri
- `--add-response-type`: Add a response type
- `--add-grant-type-supported`: Add a supported grant types e.g. --add-grant-type-supported authorization_code
- `--add-allowed-scope`: Add an allowed scope e.g. --add-allowed-scope profile
- `--add-claim-always-access-token`: Add a claim to be added to the access token e.g.
    --add-claim-always-access-token first_name --add-claim-always-access-token last_name
- `--add-claim-always-id-token`: Add a claim to be added to the id token
    e.g. --add-claim-always-id-token first_name --add-claim-always-id-token last_name
- `--add-claim-always-userinfo`: Add a claim to be added to the userinfo token
    e.g. --add-claim-always-userinfo first_name --add-claim-always-userinfo last_name
- `--add-client-param`: Add a client param e.g. --add-client-param post_logout_redirect_uri=http://some/path
- `--redirect-uris`: One or more comma separated redirect_uris
- `--response-types`: One or more comma separated response types
- `--grant-types-supported`: One or more comma separated grant types e.g. --grant-types-supported authorization_code,refresh_token
- `--allowed-scopes`: One or more comma separated allowed scopes e.g. --allowed-scopes openid,profile
- `--claims-always-access-token`: One or more comma separated claims to be added to the access token
    e.g. --claims-always-access-token first_name,birth_date
- `--claims-always-id-token`: One or more comma separated claims to be added to the userinfo token
    e.g. --claims-always-userinfo first_name,birth_date
- `--claims-always-userinfo`: One or more comma separated claims to be added to the userinfo token
    e.g. --claims-always-userinfo first_name,birth_date
- `--claims-by-scope-access-token`: Add claims by scope to the access token, e.g. --claims-by-scope-access-token true
- `--claims-by-scope-id-token`: Add claims by scope to the id token, e.g. --claims-by-scope-id-token true
- `--claims-by-scope-userinfo`: Add claims by scope to the userinfo, e.g. --add-claims-by-scope-userinfo false
- `--revoke-refresh-on-issue`: Revoke refresh tokens after they have been used
- `--pkce-essential`: Make use of PKCE is mandatory
- `--client-secret`: Change the client's secret
- `--remove-redirect-uri`: Remove a redirect_uri
- `--remove-response-type`: Remove a response type
- `--remove-grant-type-supported`: Remove a supported grant types
    e.g. --remove-grant-type-supported authorization_code
- `--remove-allowed-scope`: Remove an allowed scope e.g. --remove-allowed-scope profile
- `--remove-claim-always-access-token`: Remove a claim to be added to the access token
    e.g. --remove-claim-always-access-token first_name remove-claim-always-access-token last_name
- `--remove-claim-always-id-token`: Remove a claim to be added to the id token
    e.g. --remove-claim-always-id-token first_name --remove-claim-always-id-token last_name
- `--remove-claim-always-userinfo`: Remove a claim to be added to the userinfo token
    e.g. --remove-claim-always-userinfo first_name --remove-claim-always-userinfo last_name
- `--remove-client-param`: Remove a client param e.g. --remove-client-param post_logout_redirect_uri
