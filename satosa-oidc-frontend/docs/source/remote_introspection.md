# Remote Introspection

The OpenID Connect frontend supports remote (or fallback) introspection as an
introspection post process hook.

This enables us to forward tokens sent to our introspection endpoint to
other OPs' introspection endpoints and respond to the original request
accordingly.

This only happens if the introspection request is well-formed
and found not active by us, so it's always checked first locally.

Providers can be set under `remote_introspection_providers` introspection
post process hook kwarg in the OIDC frontend config. A provider will be
chosen based on the iss claim of the JWT payload. In the case of non-JWT,
unknown issuer or no issuer claim found in the JWT, a fallback provider can
be used set under `""`.

An example config follows:
```
config:
  [...]
  introspection_post_process_hooks:
    - class: "satosa_oidc_frontend.RemoteIntrospection",
      kwargs:
        "remote_introspection_providers":
           "https://provider.example.com/":
             client_id: test
             client_secret: secr3t
             endpoints:
                 - "https://provider.example.com/introspect"
           "":
             client_id: test
             client_secret: secr3t
             endpoints:
                 - "https://provider2.example.com/introspect"
                 - "https://provider2.example.com/introspect2"
```

As seen by the config above, each provider can have multiple
introspection endpoints set, to be used with the same credentials to
get at least one `active=True` response.

Also, setting `""` as the issuer name, sets those credentials and
endpoints as the fallback provider.