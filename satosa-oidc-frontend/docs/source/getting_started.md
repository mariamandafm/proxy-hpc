# Getting Started

This frontend is a **SATOSA plugin**: it adds an OpenID Connect Provider (OP)
to a SATOSA proxy. It is not a standalone service — you run it inside a working
SATOSA installation. This page covers installing the plugin, enabling it in
SATOSA, and bootstrapping it to the point where it can serve OIDC requests. For
setting up the SATOSA proxy itself (backends, `proxy_conf.yaml`, running the
server) see the [SATOSA documentation](https://github.com/IdentityPython/SATOSA).

## Prerequisites

- A working SATOSA installation.
- For production: a relational database. **PostgreSQL** is the operationally
  supported database; MySQL is expected to work but is not tested
  operationally. Without a database the frontend keeps all state in-memory,
  which is **not suitable for production** and is not shared across instances.

## 1. Install the plugin

```bash
pip install .
# with a database driver (PostgreSQL is the supported option):
pip install ".[postgres]"   # or ".[mysql]" (untested operationally)
```

## 2. Enable the frontend in SATOSA

Create a frontend plugin configuration file (see
[`examples/openid_connect_frontend_idpyoidc.yaml.example`](../../examples/openid_connect_frontend_idpyoidc.yaml.example)):

```yaml
module: satosa_oidc_frontend.OpenIDConnectFrontend
name: OIDC
config:
  db_uri: "postgresql://user:pass@host/db" # omit for in-memory (non-production)
  token_session_encryption_password: "<random secret>"
  # ... see the Configuration guide for all parameters
```

Reference that file from your `proxy_conf.yaml`:

```yaml
FRONTEND_MODULES:
  - "plugins/frontends/openid_connect_frontend.yaml"
```

Two configuration points are required for the frontend to start and behave
correctly:

- **`token_session_encryption_password`** must be set, or the frontend raises a
  configuration error on startup.
- The internal attribute mapped to the `sub` claim must be populated before the
  response reaches the frontend. Configure this mapping in
  `internal_attributes.yaml` (see the [Configuration](configuration.md) guide).

The full set of configuration parameters is documented in
[Configuration](configuration.md).

## 3. Initialize the database

On a clean installation with a `db_uri` set, the tables are created
automatically on first start. When upgrading the frontend later, apply schema
migrations with the `satosa-oidc-frontend-db` command. See
[Migration management](migrations.md).

## 4. Register a client

Relying Parties must exist in the client database before they can authenticate.
Create one with the `satosa-oidc-frontend-clients` command:

```bash
env SATOSA_OIDC_FRONTEND_DB_URI={db_uri} \
satosa-oidc-frontend-clients create {client_id} {client_secret} \
  --redirect-uris https://rp.example.com/callback \
  --allowed-scopes openid,email
```

See [Client Management](client_management.md) for all options, and
`client_json_path` in the [Configuration](configuration.md) guide for loading
clients in bulk from a JSON file.

## 5. Run

Start SATOSA as usual. The OP endpoints are mounted under the plugin `name`
(e.g. `OIDC`), so with an issuer of `<base_url>/OIDC` the discovery document is
served at:

```
<base_url>/OIDC/.well-known/openid-configuration
```

Endpoint paths (`token`, `userinfo`, `introspection`, ...) and which endpoints are
exposed are configurable, see the
[Miscellaneous server configuration](configuration.md#miscellaneous-server-configuration)
section.

## Next steps

- [Configuration](configuration.md): the full parameter reference
- [Client Management](client_management.md): managing clients
- [Migration management](migrations.md): schema and session migrations
- Topic guides: [Token exchange](token_exchange.md),
  [Token revocation](token_revocation.md),
  [Remote introspection](remote_introspection.md),
  [Attribute-based auth](attribute_auth.md), [Regex scopes](regex_scopes.md)
