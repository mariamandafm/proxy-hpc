# Migration management

The OpenID frontend offers the `satosa-oidc-frontend-db` command for managing the
**database schema** migrations, i.e. evolving the SQL tables (see
["The database schema"](database.md)) to the latest revision as the frontend is
upgraded. This command is a wrapper around
[alembic](https://alembic.sqlalchemy.org/en/latest/).

The following commands are offered:

- `current`: Display the current revision for a database.
- `heads`: Show current available heads
- `history`: List changeset scripts in chronological order.
- `migrate`: Migrate to a later version.
- `revision`: Create a new revision file.
- `stamp`: ‘stamp’ the revision table with the given revision

The db_uri must be provided to alembic in the same format that it was provided to the frontend's
configuration. The db_uri can either be provided through the command line arg `--db-uri`
or via the env var `SATOSA_OIDC_FRONTEND_DB_URI`.

## Applying migrations

On a new installation the tables are created automatically at the latest schema
revision, so no action is needed (as long as the database exists).

When you upgrade the frontend to a version that adds a new schema revision, apply
it by running:
`SATOSA_OIDC_FRONTEND_DB_URI={db_uri} satosa-oidc-frontend-db migrate`
