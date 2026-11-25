# Token Revocation
The OpenID Connect frontend supports Token Revocation as it is described in
[RFC 7009](https://tools.ietf.org/html/rfc7009).

In order to enable the revocation endpoint enable the `enable_revocation_endpoint` configuration parameter.

The Token Revocation endpoint path can be configured through the `revocation_path` parameter.

Token Revocation requests are handled by the `Revocation` endpoint and must contain the following attribute (as referred in [RFC 7009](https://tools.ietf.org/html/rfc7009)):
* token: The token that the client wants to get revoked

Optionally, a Token Revocation request may include:
* token_type_hint: A hint about the type of the token submitted for revocation.

Example:

A Token Revocation request to revoke a given access token.

```bash
curl -X POST "https://example.com/OIDC/revoke" \
  -u "${client_id}:${client_secret}"
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${access_token}"
```

A successful Token Revocation response is an HTTP 200

To configure token revocation the following options are available:
`token_revocation_policy`, `revocation_supported_token_types`.

`revocation_supported_token_types` configuration parameter 
defines the list of token types that are allowed to be revoked.

`token_revocation_policy` is a dictionary with the following format:
```json
{
    "": {
        "function": "/path/to/callable",
    },
    "authorization_code": {
        "function": "/path/to/callable",
    },
    "access_token": {
        "function": "/path/to/callable",
    },
    "refresh_token": {
        "function": "/path/to/callable",
    }
}
```
It is used to define different allowed policies per token type. The keys of the
dictionary are token types (`""` can be used as a fallback) and the values are
dictionaries with the keys:
 - `function`: a path to a python callable that will be called for each token revocation
   request with said token type and will decide whether the request should be
   allowed. In order to return an HTTP error the callable
   must return an `oidcmsg.oidc.TokenErrorResponse`. Defaults to
   `idpyoidc.server.oauth2.token_revocation.token_revocation_policy`