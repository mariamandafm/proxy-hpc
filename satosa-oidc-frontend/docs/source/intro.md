
# Introduction

The OpenID Connect frontend acts as an OpenID Connect Provider (OP), accepting
requests from OpenID
Connect Relying Parties (RPs). The default configuration file can be found
[here](../../examples/openid_connect_frontend_idpyoidc.yaml.example).

As opposed to the other plugins, this plugin is NOT stateless (due to the
nature of OpenID Connect using any other flow than "Implicit Flow"). However,
the frontend supports a relational database as its backend storage, so
if used with one, state can be shared between all instances.

This frontend uses the `idpy-oidc` library to implement the OP, for a full
documentation of the configurations available see
https://github.com/IdentityPython/idpy-oidc.
