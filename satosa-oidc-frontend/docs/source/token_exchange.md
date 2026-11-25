# Token Exchange
The OpenID Connect frontend supports Token Exchange as it is described in
[RFC 8693](https://tools.ietf.org/html/rfc8693). For the time being, a basic version
of the RFC is implemented meaning that only access tokens and refresh tokens can be
exchanged for new ones with a different scope set requested. (Access tokens may be
JWTs, but they are still identified by the `access_token` token type, not by a `jwt`
token type.) If unknown scopes are requested they will be
ignored if `deny_unknown_scopes=False`, else an error will be returned.

In order to enable this feature append`urn:ietf:params:oauth:grant-type:token-exchange` to the
`grant_types_supported` parameter.
Token Exchange requests are handled by the `Token` endpoint and must contain the following
attributes (as referred in [RFC 8693](https://tools.ietf.org/html/rfc8693)):
* grant_type: The value `urn:ietf:params:oauth:grant-type:token-exchange` indicates
that a token exchange is being performed.
* subject_token: A security token that represents the identity of the party on behalf of whom
the request is being made.  Typically, the subject of this token will be the subject of the security
token issued in response to the request
* subject_token_type: An identifier that indicates the type of the security token
in the "subject_token" parameter. Supported options are `urn:ietf:params:oauth:token-type:access_token`
and `urn:ietf:params:oauth:token-type:refresh_token`

Example:

First get an access token.

```bash
curl -X POST "https://example.com/OIDC/token" \
  -u "${client_id}:${client_secret}"
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "redirect_uri=https://example.com/cb" \
  -d "code=code"
```

Then send a Token Exchange request to exchange this access token with a new one (optionally for a different scope set)

```bash
curl -X POST "https://example.com/OIDC/token" \
  -u "${client_id}:${client_secret}"
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "subject_token=${access_token}" \
  -d "scope=openid email"
```

The Token Exchange response:

```json
{
   "issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
   "token_type":"Bearer",
   "access_token":"new_access_token",
   "scope":"openid email",
   "expires_in":3600
}
```

To configure token exchange the following options are available:
`token_exchange_policy`, `token_exchange_subject_token_types_supported` and
`token_exchange_requested_token_types_supported`.

`token_exchange_subject_token_types_supported` and
`token_exchange_requested_token_types_supported` are both lists that define which
subject_token_types and which requested_token_types are supported.

`default_requested_token_type` (default
`urn:ietf:params:oauth:token-type:access_token`) is the `requested_token_type`
assumed when a Token Exchange request does not specify one.

`token_exchange_policy` is a dictionary with the following format:
```json
{
    "": {
        "function": "/path/to/callable",
        "kwargs": {
            "scopes": [
                "openid"
            ]
        }
    },
    "urn:ietf:params:oauth:token-type:access_token": {
        "function": "/path/to/callable",
        "kwargs": {
            "audience": [
                "https://example.com"
            ],
            "scopes": [
                "openid"
            ]
        }
    },
    "urn:ietf:params:oauth:token-type:refresh_token": {
        "function": "/path/to/callable",
        "kwargs": {
            "resource": [
                "https://example.com"
            ],
            "scopes": [
                "openid"
            ]
        }
    }
}
```
It is used to define different allowed policies per subject_token_type. The keys of the
dictionary are `subject_token_type` (`""` can be used as a fallback) and the values are
dictionaries with the keys:
 - `function`: a path to a python callable that will be called for each token exchange
   request with said `subject_token_type` and will decide whether the request should be
   allowed. It can alter the request. In order to return an HTTP error the callable
   must return an `oidcmsg.oidc.TokenErrorResponse`. Defaults to
   `idpyoidc.server.oauth2.token_helper.validate_token_exchange_policy`
 - `kwargs`: a dict of key-value arguments that will be passed to the callable.
   Defaults to `{}`.