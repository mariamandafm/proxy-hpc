# The database schema

The frontend persists its state (sessions, tokens, clients and users) to the
relational database configured via `db_uri`. The tables are defined by this
frontend (`satosa_oidc_frontend.models`); the JSON columns (`grant_info`,
`token_args`) hold idpy-oidc's serialized session and token objects.

The tables are the following:

## User Session Table

The rows of this table are used to describe a user's session. It contains the fields:
  - `user_id`
  - `revoked`

## Client Session Table

The rows of this table are used to describe a user's session with a client. It contains the fields:
  - `client_id`
  - `user_id`
  - `revoked`

## Grant Session Table

The rows of this table are used to describe a user's grant. Each grant is tied to a user-client session. It contains the fields:
  - `client_id`
  - `user_id`
  - `grant_id`
  - `grant_type`
  - `grant_info`
  - `revoked`

`grant_info` is a JSON that contains the information about this grant, e.g.:
```json
  {
    "expires_at": 0,
    "issued_at": 1627398514,
    "not_before": 0,
    "revoked": false,
    "usage_rules": {},
    "used": 4,
    "authentication_event": {
      "idpyoidc.authn_event.AuthnEvent": {
        "uid": "test",
        "authn_info": null,
        "authn_time": 1627398514,
        "valid_until": 1627402114
      }
    },
    "authorization_request": {
      "oidcmsg.oidc.AuthorizationRequest": {
        "client_id": "ctriant",
        "state": "1599045135410-jFe",
        "scope": "openid email offline_access",
        "response_type": "code",
        "prompt": "consent",
        "redirect_uri": "https://oauth.tools/callback/code",
        "code_challenge_method": "S256"
      }
    },
    "claims": {},
    "extra": {},
    "resources": [],
    "scope": [],
    "sub": "test",
    "token_map": {
      "authorization_code": "idpyoidc.session.token.AuthorizationCode",
      "access_token": "idpyoidc.session.token.AccessToken",
      "refresh_token": "idpyoidc.session.token.RefreshToken",
      "id_token": "idpyoidc.session.token.IDToken"
    }
  }
```

## Authorization Code Table

This table is used to store authorization codes. It contains the fields:
    - `token_id`: A unique identifier for the token
    - `token_value`: the actual token value
    - `token_args`: Args used to serialize the token into a python class
    - `grant_id`: The grant_id tied to this token
    - `client_id`: The client_id of the client that created this token
    - `user_id`: The user_id of the user that this token belongs to
    - `scope`: The scope of the token
    - `revoked`: Whether this token is revoked
    - `expires_at`: When this token expires

`token_args` is a json that looks like:
```json
{
    "claims": {},
    "expires_at": 1638174882,
    "id": "7f51591350ee11ec97d60d3b0237b7cc",
    "issued_at": 1638174582,
    "name": "AuthorizationCode",
    "not_before": 0,
    "resources": [],
    "revoked": false,
    "scope": [
        "openid"
    ],
    "token_class": "authorization_code",
    "usage_rules": {
        "expires_in": 300,
        "max_usage": 1,
        "supports_minting": [
            "access_token",
            "id_token",
            "refresh_token"
        ]
    },
    "used": 0
}
```

## Access Token Table

This table is used to store access tokens. It contains the fields:
    - `token_id`: A unique identifier for the token
    - `token_value`: the actual token value
    - `token_args`: Args used to serialize the token into a python class
    - `grant_id`: The grant_id tied to this token
    - `client_id`: The client_id of the client that created this token
    - `user_id`: The user_id of the user that this token belongs to
    - `scope`: The scope of the token
    - `revoked`: Whether this token is revoked
    - `expires_at`: When this token expires
    - `based_on`: Which token was used to issue this token, can be an authorization code or a refresh token
    - `refresh_token`: The refresh token that was issued with this access token, if one was issued
    - `token_type`: The token type

`token_args` is a json that looks like:
```json
{
    "claims": {},
    "expires_at": 1638178182,
    "id": "7f51591550ee11ec97d60d3b0237b7cc",
    "issued_at": 1638174582,
    "name": "AccessToken",
    "not_before": 0,
    "resources": [],
    "revoked": false,
    "scope": [
        "openid"
    ],
    "token_class": "access_token",
    "token_type": "bearer",
    "usage_rules": {
        "expires_in": 3600
    },
    "used": 0
}
```

## ID Token Table

This table is used to store id tokens. It contains the fields:
    - `token_id`: A unique identifier for the token
    - `token_value`: the actual token value
    - `token_args`: Args used to serialize the token into a python class
    - `grant_id`: The grant_id tied to this token
    - `client_id`: The client_id of the client that created this token
    - `user_id`: The user_id of the user that this token belongs to
    - `scope`: The scope of the token
    - `revoked`: Whether this token is revoked
    - `expires_at`: When this token expires
    - `based_on`: Which token was used to issue this token, can be an authorization code or a refresh token

`token_args` is a json that looks like:
```json
{
    "claims": {},
    "expires_at": 0,
    "id": "7f51591750ee11ec97d60d3b0237b7cc",
    "issued_at": 1638174582,
    "name": "IDToken",
    "not_before": 0,
    "resources": [],
    "revoked": false,
    "scope": [
        "openid"
    ],
    "token_class": "id_token",
    "usage_rules": {},
    "used": 0
}
```

## Refresh Token Table

This table is used to store refresh tokens. It contains the fields:
    - `token_id`: A unique identifier for the token
    - `token_value`: the actual token value
    - `token_args`: Args used to serialize the token into a python class
    - `grant_id`: The grant_id tied to this token
    - `client_id`: The client_id of the client that created this token
    - `user_id`: The user_id of the user that this token belongs to
    - `scope`: The scope of the token
    - `revoked`: Whether this token is revoked
    - `expires_at`: When this token expires
    - `based_on`: Which token was used to issue this token, can be an authorization code or a refresh token

`token_args` is a json that looks like:
```json
{
    "based_on": "Z0FBQUFBQmhwSkZWN3BUalJ5b0g3QXhCSjQ4Z3Frb0FSOFlxZ09QTU9tZ2FrTHlla2w0a29tNndFaU81MHZMTUg3eGNJU3NmZk9rRWNUQ24zakt6aWkyZ21GQmNDdTVNQldpVW1hbVVkNEhheEs5NzlETnJuR3RUeGI1UVFOR0lOOVJvYTFGczN2T1JUWXZVZTVxWXBtc0pjdVFOdm9uRUZ5SVpIYWYyd1pUNk1PVzdMTDJZRmV0THdzUHdUMU5Hc2d3WGt4ZkYyS0Q1aVZvVUg1WUctdG4wVFBUc3lLSTFlY1F5aS1ZWk9hcXo4TkVCNzVvMWJsX1M1aDk3X05wdGduVTl4eF9uZzJOMDZfVUhZME1rTlNnQ2x0TkV4ZDFLUmdmc3hUQTBTUm55MERCVldacnhMaF9abk95emVycDZ2c2R0Y0lzenkzOFROcGhIVHdLd2YtYVNwdXUxOS1WdHk4UXlaeEJ4SlJLSTg4QVRoSTM3MmVoZlc1VjFUaWdpZVJ1eWx3dTV5NEFHellNZ2tZOThZWGxzbGN0dkhzZEt4SGpZbzB2b21fbEZBYWRZMmpnTDhGMl9mZUpGc1RfSG11cG5vd0p2RTIwdEhGTWlZcHlvRk1saG5hbDVndW8tcmNxazU2UUljZjNyN21YLWZqY1E5VUVicUtFNkdHYWE2Q1FUQXFRN0ZxZTNsV1IzcTd3OHIyeFBRUVJoQUJIOTc5bzkwTE9FYTRSV3FwLWZhckhQcnhJaDdVZlhTVHhtQmR0YmdwRW9iNi13VFVSSlpfaUlOQ1FCZEZiV2tZZXlTN0ZBV2VmMkJMMVlwc2ZYV2dRREJhcndTQ09oUFRreDNwcF9kejJqNXBJRg==",
    "claims": {},
    "expires_at": 1638261461,
    "id": "9d48b08350ef11ec97d60d3b0237b7cc",
    "issued_at": 1638175061,
    "name": "RefreshToken",
    "not_before": 0,
    "resources": [],
    "revoked": false,
    "scope": [
        "openid",
        "offline_access"
    ],
    "token_class": "refresh_token",
    "usage_rules": {
        "expires_in": 86400,
        "supports_minting": [
            "access_token",
            "refresh_token",
            "id_token"
        ]
    },
    "used": 0
}
```

## Client Database

The client database holds all registered clients. The structure is based on a key-value mapping where
the key is the client_id and the value is a dict itself with client and preferences.

```json
{
    "oidc_app": {
        "application_type": "web",
        "redirect_uris": [["https://example.com/OIDC/callback", ""]],
        "client_secret": "ZXhh213fjafjacmV0",
        "response_types": ["code"],
        "allowed_scopes": [
            "openid",
            "email"
        ],
         "add_claims": {
            "always": {
                "introspection": [
                    "name",
                    "nickname",
                    "email"
                ],
                "id_token": {
                    "email": null
                },
                "access_token": {
                    "email": null
                }
            },
            "by_scope": {
                "id_token": true
            }
        }
    }
}
```

This has been implemented in the frontend as a table with two columns: a `client_id` (primary_key) string and a JSON `client_info`.

### Client configuration

Further documentation about the client configuration can be found at:
- https://idpy-oidc.readthedocs.io/en/latest/server/contents/clients.html

A few options described there:
- `Static Client configuration`
- `client_secret`
- `client_secret_expires_at`
- `redirect_uris`
- `auth_method`
- `request_uris`
- `response_types`
- `grant_types_supported`
- `scopes_to_claims`
- `allowed_scopes`
- `revoke_refresh_on_issue`
- `add_claims` (`always` and `by_scope)`
- `token_usage_rules`
- `pkce_essential`
- `post_logout_redirect_uri`
- `backchannel_logout_uri`
- `frontchannel_logout_uri`
- `request_object_signing_alg`
- `request_object_encryption_alg`
- `request_object_encryption_enc`
- `userinfo_signed_response_alg`
- `userinfo_encrypted_response_enc`
- `userinfo_encrypted_response_alg`
- `id_token_signed_response_alg`
- `id_token_encrypted_response_enc`
- `id_token_encrypted_response_alg`
- `dpop_jkt`
- `application_type`
- `required_acrs`

Specifically for `application_type`, it can take two possible values: `"web"` (default) and `"native"`.
Setting the value to `"native"` can allow variable port numbers for redirect uris (per RFC8252).

The `required_acrs` parameter (optional) defines the Authentication Context Class Reference levels that a client requires for authentication. It ensures that users authenticate using methods that meet specified security levels. It is an array of strings (e.g `["urn:mace:incommon:iap:silver","urn:mace:incommon:iap:gold"]`).

## User Database

The user database holds user data and is read-only. The representation again relies on a key-value pairing
where the key is the user_id and the value is a dict itself with user attributes.

```json
{
    "diana": {
        "sub": "dikr0001",
        "name": "Diana Krall",
        "given_name": "Diana",
        "family_name": "Krall",
        "nickname": "Dina",
        "email": "diana@example.org",
        "email_verified": false,
        "phone_number": "+46907865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
        "eduperson_scoped_affiliation": [
            "staff@example.org"
        ]
    }
}
```

In the satosa-oidc-frontend it has been implemented as a table with two columns: a `user_id` (primary_key) string and a JSON `user_info`.
