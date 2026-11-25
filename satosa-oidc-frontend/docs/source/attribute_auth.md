# Attribute Auth

The OpenID frontend includes a custom authn/authz method that allows requiring
valid user tokens with arbitrary user attributes and values in order to access
an endpoint.

This is mostly related to (authenticated) registration that can benefit from this
kind of auth mechanism, but the class is endpoint-agnostic based on the idpy-oidc's
authentication class interface.

By default, AttributeAuth works as a simple Bearer header method. E.g. setting the following
will force the registration endpoint to require a user's valid access token to register a new
client:

```
client_authn_method_mapping:
    attribute_auth: satosa_oidc_frontend.AttributeAuth
registration_authn:
    - attribute_auth
```


To configure AttributeAuth to check for attributes a configuration like the following is required:

```
attribute_auth:
    eduperson_scoped_affiliation:
        - staff@example.com
        - admin@example.com
    eduPersonTargetedID:
        - staffa
        - adminb
```

This will require that the user authenticating has BOTH those attributes
in her `user_info` with EITHER value set in the config for the respective
attribute.