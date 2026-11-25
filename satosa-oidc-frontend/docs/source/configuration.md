# Configuration

For starters, the user is required to configure an appropriate mapping for the
`sub` claim in `internal_attributes.yaml`. The user **must** ensure that the
internal attribute that is mapped to the `sub` claim will have a value before
processing reaches the frontend's response handler.


## Parameter configuration

The configuration parameters that SATOSA OIDC Frontend supports affect the frontend's behavior globally but some of them can be also configured explicitly to affect specific clients by overriding the global configuration.

In the next sections the available configuration parameters available are presented.


### Client Authentication

- **`client_authn_method`** (default: `[
    "client_secret_basic", "client_secret_post", "bearer_header",
    "bearer_body", "client_secret_jwt", "private_key_jwt" ]`)
    
    List of all available client authentication
    methods for the token and introspection endpoints. The available options are:
    - `none`: No authentication is required, this should be used for testing purposes only
    - `public`: Only a valid `client_id` is required in the requests body
    - `client_secret_basic`: HTTP Basic authentication
    - `client_secret_post`: The Client Credentials must be included in the request body
    - `bearer_header`: See https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
    - `bearer_body`: See https://datatracker.ietf.org/doc/html/rfc6750#section-2.2
    - `client_secret_jwt`: See https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
    - `private_key_jwt`: See https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

   **Per-client configuration supported.** It is possible to enable a `client_authn_method` for some clients only, eg. some clients may be
public while some others may not. This behavior can be achieved by defining client authentication
methods per client for each endpoint, e.g.:

    ```
    # frontend_config.yaml
    ...
    client_authn_method:
        - client_secret_basic
        - client_secret_post
        - public
    ```
    client A metadata:
    ```
    {
        ...,
        "token_endpoint_client_authn_method": ["public"]
    }
    ```

    client B metadata:
    ```
    {
        ...,
        "token_endpoint_client_authn_method": ["client_secret_basic", "client_secret_post"]
    }
    ```

    With this configuration client A will be able to use only `public` authentication on the token endpoint,
    while client B will be able to use only `client_secret_basic` and `client_secret_post`.

    The available per client options are:
    - `authorization_endpoint_client_authn_method`
    - `token_endpoint_client_authn_method`
    - `introspection_endpoint_client_authn_method`
    - `userinfo_endpoint_client_authn_method`
    - `registration_endpoint_client_authn_method`
    - `revocation_endpoint_client_authn_method`

    Note that the authentication methods defined per client must be a subset of the authentication methods
    defined globally, so if we removed `public` from the frontend's `client_authn_method`, client A wouldn't
    be able to authenticate as a public client even after we add it to its metadata.

- **`client_authn_method_mapping`**

    A mapping for custom client authentication methods. The
    keys are the methods' names and the values are paths to the python classes that will be called to
    validate the client. The python classes must implement the API defined by `idpyoidc.client_authn.ClientAuthnMethod`,
    for an example see the [Attribute Auth section](#attribute-auth).
    After defining an authentication method in this mapping it must be added to the `client_authn_method` list in order
    to activate it.

- **`registration_authn`** (default: `["bearer_header", "bearer_body"]`)

    List of all available client authentication methods for the registration endpoint. The available options are the same as for
    `client_authn_method`

### Scope and Claims

- **`scopes_to_claims`**

    A dictionary defining a mapping from scopes to claims. Defaults to the scopes mapping described in https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims :
    

    ```json
    {
        "openid": ["sub"],
        "profile": [
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
            "preferred_username"
        ],
        "email": ["email", "email_verified"],
        "address": ["address"],
        "phone": ["phone_number", "phone_number_verified"],
        "offline_access": []
    }
    ```
    If we want to define a scope that doesn't map to claims (e.g `offline_access`) then we
    simply map it to an empty list:
    ```json
    {
        "scope_a": ["claim1", "claim2"],
        "scope_b": []
    }
    ```
    **Note**: The `openid` scope must always be in the mapping, even if it is omitted it will be automatically be added

- **`allowed_scopes`**
    
    A list with the scopes that are allowed to be used. If `scopes_to_claims` is defined, then `allowed_scopes` defaults to the keys in the `scopes_to_claims` mapping.

- **`claim_rules`**
    
    A dictionary defining rules that determine how specific claims should be handled based on the requested scopes. 
    ```json
    {
        "require_scopes": ["entitlements"],
        "claim_name": "...",
        "allowed_values": [...],
    }
    ```
    **`require_scopes`**: Specifies which scopes must be present in the request for this rule to be applied. 
    **`claim_name`**: The name of the claim that will be populated based on the rule.
    **`allowed_values`**: Specifies the allowed values for the claim. Can include wildcard patterns (e.g., urn:geant:domain\.tld:res:res1:act:(admin|viewer)) to match multiple values.

    **Note**: In order for specific claims to be included in the response, the scopes related to those claims must also be present in the `allowed_scopes` of the client configuration.

- **`scopes_supported`**

    A list with the scopes that will be advertised in the well-known
    endpoint. Defaults to the value of `allowed_scopes`.

    **Per-client configuration supported.**

- **`claims_supported`** (default: `[]`)

    A list with the claims that will be advertised as supported in the
    well-known endpoint. If left empty it is derived from the configured
    `scopes_to_claims` mapping.

- **`claim_types_supported`** (default: `["normal", "aggregated",
    "distributed"]`): 
    
    List of all the claim types supported.

- **`id_token_default_claims`** (default: `[]`)

    A list with all the claims that should be added to every id token

- **`add_claims`**

    Strictly formatted dictionary that defines the behavior of claims.
    
    For more information consider the [idpy-oidc documentation](https://github.com/IdentityPython/idpy-oidc).

    **Per-client configuration supported.**


- **`id_token_add_claims_by_scope`** (default: `False`)

    Whether scopes should be used to add claims to the ID token.

- **`deny_unknown_scopes`** (default: `True`)

    Controls the issuing of tokens with unknown scopes requested.

    **Per-client configuration supported.**

- **`jwt_access_token`** (default: `False`)

    Whether access tokens should be issued as signed JWTs. When `False`, access tokens are opaque (encrypted) strings. When `True`, the JWT access token handler is used and claims can be added to the access token via `access_token_claims` and the scope-to-claim mapping.

- **`access_token_claims`** (default: `[]`)

    The claims to add to the access tokens, this parameter should only be used in conjunction with `jwt_access_token`.

- **`enable_introspection_claims_per_client`** (default: `False`)

    Whether configurable claims per client are allowed for the introspection response. The claims can then be configured in the clients json file or in the DB.

- **`at_enable_claims_per_client`** (default: `False`)

    Whether configurable claims per client are allowed for the access token/user info endpoint. The claims can then be configured in the clients json file or in the DB.

- **`id_token_enable_claims_per_client`** (default: `False`)

    Whether configurable claims per client are allowed for the id token. The claims can then be configured in the clients json file or in the DB.

- **`userinfo_enable_claims_per_client`** (default: `False`)

    Whether configurable claims per client are allowed for the userinfo. The claims can then be configured in the clients json file or in the DB.

- **`activate_regex_scopes`** (default: `False`)

    Whether to enable the support for regex scopes

- **`allowed_scopes_regex`** (default `[]`)

    A list of regexes that scopes may conform to.


### Tokens Configuration

- **`access_token_lifetime`** (default: `3600`)

    How long access tokens should be valid.

    **Per-client configuration supported**. The access token lifetime can be configured for a specific client in order to override the global access token lifetime by defining appropriately the `token_usage_rules` dictionary in the client metadata, e.g.:
    ```
    {
        "token_usage_rules": {
            "access_token": {
                "expires_in": lifetime
            }
            ...
        }
        ...
    }
    ```

- **`id_token_lifetime`** (default: `300`)

    How long id_tokens tokens should be valid.

    **Per-client configuration supported**. The id token lifetime can be configured for a specific client in order to override the global id token lifetime by defining appropriately the `token_usage_rules` dictionary in the client metadata, e.g.:
    ```
    {
        "token_usage_rules": {
            "id_token": {
                "expires_in": lifetime
            }
            ...
        }
        ...
    }
    ```

- **`code_lifetime`** (default: `300`)

    How long access code should be valid.

    **Per-client configuration supported**. The authorization code lifetime can be configured for a specific client in order to override the global authorization code lifetime by defining appropriately the `token_usage_rules` dictionary in the client metadata, e.g.:
    ```
    {
        "token_usage_rules": {
            "code": {
                "expires_in": lifetime
            }
            ...
        }
        ...
    }
    ```

- **`refresh_token_lifetime`** (default: `86400`)

    How long refresh tokens should be valid.

    A `refresh_token_lifetime` of 0 means that the refresh tokens will never expire. In previous versions (`<1.3.0`) a value of 0 meant that no refresh token would be issued. The issuing of refresh tokens is controlled solely with `grant_types_supported` (and `offline_access` scope).

    **Per-client configuration supported**. The refresh token lifetime can be configured for a specific client in order to override the global refresh token lifetime by defining appropriately the `token_usage_rules` dictionary in the client metadata, e.g.:
    ```
    {
        "token_usage_rules": {
            "refresh_token": {
                "expires_in": lifetime
            }
            ...
        }
        ...
    }
    ```

### Miscellaneous server configuration

- **`issuer`**

    The issuer identifier of the OP. Defaults to `<base_url>/<name>`, where `<name>` is the SATOSA plugin name. Setting it explicitly is only needed when the issuer must differ from the derived URL.

- **`authorization_path`** (default: `<name>/authorization`)

    The path of the authorization endpoint.
- **`token_path`** (default: `<name>/token`)
    
    The path of the token endpoint.

- **`userinfo_path`** (default: `<name>/userinfo`)

    The path of the userinfo endpoint.

- **`registration_path`** (default: `<name>/registration`)

    The path of the registration endpoint.

- **`enable_registration_endpoint`** (default: `False`)
    
    Whether to expose the registration endpoint.

- **`client_secret_expiration_time`** (default: `432000`)

    How long (in seconds) the secret of a dynamically registered client remains valid. Applies to clients created through the registration endpoint.

- **`introspection_path`** (default: `<name>/introspection`)
    
    The path of the introspection endpoint.

- **`enable_introspection_endpoint`** (default: `False`)

    Whether to expose the introspection endpoint.

- **`introspection_post_process_hooks`**

    A list of hooks to run after a request to the introspection is done being processed. Each hook must expect the parameters: `args, parsed_request, token, context`:
    - `args`: A dictionary with the key-value:

      `'response_args': <oidcmsg.oauth2.TokenIntrospectionResponse>`
    - `token`: The token from parsed_request
    - `parsed_request`: An `oidcmsg.oauth2.TokenIntrospectionRequest`
    - context: The `satosa.context.Context`

  Each hook will return an updated dictionary which
  will be provided to the next hook or will be returned as response (if this is the last hook).
  For information on how to use these configurations see the
  ["Hook configuration" section](#hook-configuration).

- **`userinfo_post_process_hooks`**

    A list of hooks to run after a request to the userinfo is done being processed. Each hook must expect the parameters: `args, parsed_request, token, context`:
    - `args`: A dictionary with the key-value:

      `'response_args': <oidcmsg.oauth2.UserInfoResponse>`
    - `token`: The token from parsed_request
    - `parsed_request`: The parsed request from userinfo
    - context: The `satosa.context.Context`

  Each hook will return an updated dictionary which
  will be provided to the next hook or will be returned as response (if this is the last hook).
  For information on how to use these configurations see the
  ["Hook configuration" section](#hook-configuration).

- **`token_revocation_path`** (default: `<name>/revoke`)

    The path of the revocation endpoint.

- **`enable_revocation_endpoint`** (default: `False`)

    Whether to expose the revocation endpoint.

- **`revocation_supported_token_types`** (default: `["authorization_code", "access_token", "refresh_token"]`)

    The list representing the supported token types for revocation.

- **`token_revocation_authn`** (default: `["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "bearer_header", "bearer_body"]`)

    List of the client authentication methods available on the revocation endpoint. The available options are the same as for `client_authn_method`.

- **`token_revocation_policy`**

    Controls the policies that allow a token revocation to take place for more details see the ["Token revocation" section](#token-revocation).

- **`jwks_private_path`** (default: `None`)

    Path to a file:

    - If the file exists and a JWKS is found there.
      From that JWKS a KeyJar instance is built.
    - If the private path file doesn't exist the key definitions are
      used to build a KeyJar instance. A JWKS with the private keys are
      written to the file named in private_path.

- **`jwks_public_path`** (default: `None`)

    Path to a file:
    
    - If the public path file exists then the JWKS in that file is used to construct a KeyJar.
    - If no such file exists then a KeyJar will be built
      based on the key_defs specification and a JWKS with the public keys
      will be written to the public path file.

- **`jwks`** (default: `[
      {"type": "RSA", "use": ["sig"]},
      {"type": "EC", "crv": "P-256", "use": ["sig"]}
    ]`)
    
    A JSON representing the keys that are to be created, or found in the
    provided paths, the JSON is a list where each element represents a
    different key. Each element is a dictionary with the following keys:
    - `type`:
        The type of key. Presently only 'rsa', 'oct' and 'ec'
        supported.
    - `key`:
        A name of a file where a key can be found. Only works
        with PEM encoded RSA keys
    - `use`:
        What the key should be used for
    - `crv`:
        The elliptic curve that should be used. Only applies to
        elliptic curve keys
    - `kid`:
        Key ID, can only be used with one usage type is
        specified. If there are more the one usage type specified
        'kid' will just be ignored.

- **`jwks_read_only`** (default: `False`)

    If SATOSA should not attempt to write anything to the file system when creating the jwks.

- **`jwks_uri`** (default: `jwks`)

    The path, relative to the OP base URL, at which the provider's JWKS (public keys) is published.

- **`db_uri`**

    Connection URI to an SQL instance where session, client and user
    data will be persisted. If it's not specified all data will only be stored
    in-memory (not suitable for production use).

    **PostgreSQL** is the operationally supported database (e.g.
    `postgresql://user:pass@host/db`). MySQL is expected to work but is not
    tested operationally.

- **`enforce_audience_restriction`** (default: `False`)

    Use this option to enforce  audience restrictions on the introspection endpoint

- **`client_credentials_policy`**

    Controls the policy applied to the OAuth2 `client_credentials` grant on the token endpoint. It has the same shape as `token_revocation_policy` / `token_exchange_policy`: a dictionary keyed by token type (`""` as a fallback), whose values are dictionaries with a `function` (a path to a callable that decides whether the request is allowed) and optional `kwargs`. Defaults to `satosa_oidc_frontend.helpers.client_credentials_filter_policies.validate_client_credentials_filter_policy`.

- **`client_json_path`**
    
    A path to a JSON file that contains clients for the
    initial loading of the client db. 
    
    **Note**: When a database is used for the client db, whether existing
    clients are overwritten on import is controlled by `overwrite_clients_in_db`.

- **`overwrite_clients_in_db`** (default: `True`)

    When importing clients from `client_json_path`, whether to overwrite clients
    that already exist in the database. When `True` (the default) the imported
    definitions replace the existing rows; when `False` only clients that are not
    already present are added.

- **`provider`**

    A dictionary that will be passed through to the idpy-oidc, the use of this parameter is not advised.

- **`pkce`** (default: `True`)

    Configures whether PKCE is enabled. The value can also be
    a dict with two keys: `essential` and `code_challenge_methods`. Setting `pkce`
    to `True` is the same as:
    ```
    - essential: False
    - methods:
        - S256
    ```
    **Per-client configuration supported.** Configuring pkce per client is possible by defining `pkce_essential` in the client metadata.

- **`token_session_encryption_password`**

    The key used to encrypt the session id. Something random should be used for this.
- **`token_encryption_password`** (default: `""`)

    The key used to encrypt the non JWT tokens. Non JWT tokens are encrypted strings containing the session id of that token.
- **`revoke_refresh_on_issue`** (default: `False`)

    Whether the refresh token used to issue a new refresh token will be revoked.

    **Per-client configuration supported.**

- **`response_types_supported`** (default: `[ "code", "token", "id_token", "code token", "code id_token", "id_token token", "code id_token token" ]`) 

    List of all supported
    response types, see [Section 3 of OIDC Core](http://openid.net/specs/openid-connect-core-1_0.html#Authentication).

    **Per-client configuration supported.**

- **`grant_types_supported`** (default: `["authorization_code", "implicit"]`):

    List of all the grant types supported.

    **Per-client configuration supported.**

- **`response_modes_supported`** (default: `["query", "fragment", "form_post"]`)

    List of all the response modes supported.

- **`subject_types_supported`** (default: `["pairwise"]`):

    List of all the subject types supported.

- **`schemes_denylist`** (default: `None`)

    A list of URI schemes that are not allowed for client `redirect_uris` at the authorization endpoint. When unset, no scheme-based restriction is applied.

- **`sub_func`**

    A mapping of subject (`sub`) generation functions keyed by subject type (`public`, `pairwise`), used when building the value of the `sub` claim for a session. This is an advanced option; the defaults are normally sufficient.

- **`client_db_handler_class_path`**

    The path to the class API that will handle the DB used for the clients.

    - If the database used in `db_uri` is desired, this must be set to:
        `"satosa_oidc_frontend.frontend.ClientDB"`
    - If the database used in `db_uri` is desired, and secrets are expected to be hashed
        (e.g. `client_db_enable_secret_hashing_on_import` is `true`), this must be set to:
        `"satosa_oidc_frontend.frontend.ClientDBHashedSecrets"`
    - If Letty will be used, this must be set to:
        `"satosa_oidc_frontend.libraries.letty_api.LettyClientsAPI"`
    - If left blank, an in memory dictionary will be used as the database

- **`client_db_handler_class_kwargs`**

    The kwargs that will be used when instantiating the class from `client_db_handler_class_path`

    - If the database used in `db_uri` is desired, this can be left blank
    - If a separate DB URI will be used for `satosa_oidc_frontend.frontend.ClientDBHashedSecrets`,
      this can be set to: `{"db_uri": <client_db_uri>}`. This assumes that the separate DB has
      an existing `client` table.
    - If Letty will be used, this must be set to: `{"api_url": <letty_api_url>}`

- **`client_db_enable_import`**

    The boolean flag to indicate whether to import the clients defined in
    `client_json_path`

    - If Letty will be used, this must be set to `false` as it is not currently supported

- **`client_db_enable_secret_hashing_on_import`**

    The boolean flag to indicate whether client secrets need to be hashed during import to the Client DB.
    This is recommended to be `true` *if* the file from `client_json_path` stores secrets in plain text.

- **`enable_resource_indicators`**

    The boolean flag to indicate whether the resource indicators policies are enabled
    
- **`resource_indicators`**

    The resource indicators policies that will be applied. It ensures that only authorized clients can request access to designated resource servers, e.g.:
    ``` 
    "resource_indicators": {
        "policy": {
            "function": "idpyoidc.server.oauth2.token_helper.validate_resource_indicators_policy",
            "kwargs": {
                "resource_servers_per_client": ["client2", "client3"]
            }
        }    
    }
    ```

    - `policy`:

      The policy object defines the validation function and its parameters used to enforce access control.

      - `function`: Specifies the function responsible for validating the resource indicators policy. In this case, it is idpyoidc.server.oauth2.token_helper.validate_resource_indicators_policy.
    
      - `resource_servers_per_client` 
      
        Defines the allowed resource servers per client.

- **`enable_audience_policies`**

    The boolean flag to indicate whether the audience policies are enabled
    
- **`audience_policies`**

    The audience policies that will be applied. These audience policies can be either applied globally or per-client.
    The per-client configuration overrides any global configuration, e.g.:
    ``` 
    "": [
            {
            "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
            }
        ],
        "client1": [
            {
            "function": "satosa_oidc_frontend.helpers.audience_policies.checkRefreshTokenRequest",
            }
        ]
    ```
    If the audience policy fails, the function must correctly set `request["error"]` and `request["error_description"]`.
    E.g.:
    ```
    def checkRefreshTokenRequest(request, context, client_info, audience, grant, **kwargs):
        msg = f"Client Id: {request['client_id']}, Requested Resources: {request.get('resource', '')}"
        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(None), message=msg
        )
        logger.info(logline)
        if isinstance(request, RefreshAccessTokenRequest):
            if "client2" not in audience:
                request['error'] = "audience_policy_error"
                request['error_description'] = "client3 resource not in the request"
        else:
          print("Continue as the request is not a RefreshAccessTokenRequest object.")
    ```

## Hook configuration

Hooks will allow to customize each endpoint's functionality by configuring
a class to run after the endpoint has processed a request.
Each hook takes a configuration in the following format:
```
config:
  [...]
  endpoint_hooks:
    - class: SomeClass
    - class: SomeClass2
      function: foo
    - class: SomeClass3
      kwargs:
        a: 1
        b: 2
    - class: SomeClass4
      function: foo
      kwargs:
        arg: 1
```
If the hook is a class then kwargs are used to initialize the class and
the provided function is called when the hook is run. If no function is
provided then the class is called.

The hooks are called in the order they were configured.

Currently, hooks can only be configured as `introspection_post_process_hooks` or `userinfo_post_process_hooks`. For an
example configuration check ["Remote introspection"](#remote-introspection).

### RemoteDataProvider
With this hook you can fetch remote info, from an endpoint using Basic Auth.
```
{
    "class": "satosa_oidc_frontend.RemoteDataProvider",
    "kwargs": {
        "remote_endpoints": [ 
            {
                "wrap_claim_name": "my_custom_claim", 
                "ignore_api_error": False,
                "api_url": "https://provider2.example.com/userinfo",
                "api_username": "foo",
                "api_password": "bar",
                "api_timeout": 60,
                "api_retries": 3
            }
        ]
    },
}
```
- **`wrap_claim_name`**
  
Optional. The claim name where the remote information will be stored. If not set, the remote information will be added on the same level as the rest of the claims.

- **`ignore_api_error(default: False)`**

Optional. If is set to False, will fail the request if an error occurs.


- **`api_url`**

The URL of the external provider’s UserInfo endpoint. This is where the system will send a request to retrieve the user's claims.

- **`api_username`**

Username for basic authentication with the external UserInfo API. Used in combination with api_password.

- **`api_password`**

Password for basic authentication with the external UserInfo API, used alongside api_username.

- **`api_timeout`**

Specifies the timeout (in seconds) for the API request to the UserInfo endpoint. If the request takes longer than this value, it will be terminated.

- **`api_retries`**

Number of retry attempts for the API call.