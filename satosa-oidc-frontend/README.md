# SATOSA OIDC Frontend

An OpenID Connect frontend for [SATOSA](https://github.com/IdentityPython/SATOSA),
built on [`idpy-oidc`](https://github.com/IdentityPython/idpy-oidc).

## Description

The OpenID Connect frontend turns the SATOSA proxy into an OpenID Connect
Provider (OP): it accepts requests from OpenID Connect Relying Parties (RPs)
and translates them onto SATOSA's internal protocol so they can be served by
any configured backend.

Unlike most SATOSA plugins, this frontend is **not stateless**, OpenID Connect
flows other than the Implicit Flow require server-side state. The frontend can
persist that state (sessions, tokens and clients) to a relational database, so
that state is shared across all instances. Without a database, state is kept
in-memory only, which is **not suitable for production**.

The OP itself is implemented with the `idpy-oidc` library; for the full set of
underlying options see the
[idpy-oidc documentation](https://github.com/IdentityPython/idpy-oidc).

## Documentation

Topic guides live under [`docs/source/`](docs/source/):

- [Introduction](docs/source/intro.md)
- [Getting Started](docs/source/getting_started.md) — install, enable the plugin in SATOSA, and bootstrap it
- [Configuration](docs/source/configuration.md) — all configuration parameters
- [Client management](docs/source/client_management.md) — the `satosa-oidc-frontend-clients` CLI
- [Database & migrations](docs/source/database.md) and [Migrations](docs/source/migrations.md) — the `satosa-oidc-frontend-db` CLI
- [Regex scopes](docs/source/regex_scopes.md)
- [Attribute-based auth](docs/source/attribute_auth.md)
- [Token exchange](docs/source/token_exchange.md) (RFC 8693)
- [Token revocation](docs/source/token_revocation.md) (RFC 7009)
- [Remote introspection](docs/source/remote_introspection.md)

The docs are also buildable as a Sphinx site (`docs/`).

## Installation

```bash
pip install .
```

Optional database drivers are available as extras:

```bash
pip install ".[postgres]"   # psycopg2
pip install ".[mysql]"      # PyMySQL
```

PostgreSQL is the operationally supported database. MySQL is expected to work
but is not tested operationally.

## Usage

This is a SATOSA plugin: enable it as a frontend in a SATOSA proxy by pointing a
frontend plugin config at the module and providing the OP configuration. A
minimal example is in
[`examples/openid_connect_frontend_idpyoidc.yaml.example`](examples/openid_connect_frontend_idpyoidc.yaml.example):

```yaml
module: satosa_oidc_frontend.OpenIDConnectFrontend
name: OIDC
config:
  # ... see docs/source/configuration.md for all parameters
```

For step-by-step setup, installing, enabling the plugin, initializing the
database and registering a client, see the
[Getting Started](docs/source/getting_started.md) guide.

The package installs two CLIs:

- `satosa-oidc-frontend-clients` — manage clients ([docs](docs/source/client_management.md))
- `satosa-oidc-frontend-db` — run database schema migrations ([docs](docs/source/migrations.md))

## Development

```bash
pip install -e . -r requirements/test.txt
pytest -vvv -ra tests/
```

This repo uses [`pre-commit`](https://pre-commit.com/) (black, isort) — install
the hooks with `pre-commit install`. Linting/formatting config lives in
`pyproject.toml`.

## License

Licensed under the Apache License 2.0 — see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE). Developed on behalf of the GÉANT Project.
