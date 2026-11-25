import os

import click
from alembic import command, script
from alembic.config import Config
from alembic.runtime import migration
from sqlalchemy import create_engine

from satosa_oidc_frontend.alembic.utils import get_alembic_ini


@click.group()
@click.option(
    "--db-uri",
    type=str,
    help="A db_uri to use in order to connect to the database, defaults to env "
    "var 'SATOSA_OIDC_FRONTEND_DB_URI'",
    default=lambda: os.environ.get("SATOSA_OIDC_FRONTEND_DB_URI", ""),
)
@click.pass_context
def cli(ctx, db_uri):
    conf_path = get_alembic_ini()
    alembic_cfg = Config(conf_path)
    alembic_cfg.set_main_option("script_location", "satosa_oidc_frontend:alembic")
    alembic_cfg.set_main_option("sqlalchemy.url", db_uri)
    ctx.obj = dict(alembic_config=alembic_cfg)


@cli.command()
@click.pass_context
@click.argument("revision", default="head")
def migrate(ctx, revision):
    """Migrate to a later version."""
    config = ctx.obj["alembic_config"]
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    directory = script.ScriptDirectory.from_config(config)
    with engine.begin() as connection:
        context = migration.MigrationContext.configure(connection)
        migration_needed = set(context.get_current_heads()) != set(
            directory.get_heads()
        )
        current_revision = context.get_current_revision()
    if not migration_needed:
        click.echo("No migration needed, db is up to date")
        return

    if revision == "head":
        revision = directory.get_current_head()
    click.echo(f"Migrating from revision {current_revision} to {revision}")
    command.upgrade(config, revision)


@cli.command()
@click.pass_context
def current(ctx):
    """Display the current revision for a database."""
    command.current(ctx.obj["alembic_config"])


@cli.command()
@click.pass_context
def heads(ctx):
    """Show current available heads"""
    command.heads(ctx.obj["alembic_config"])


@cli.command()
@click.pass_context
@click.argument("revision")
def stamp(ctx, revision):
    """
    ‘stamp’ the revision table with the given revision; don’t run any
    migrations.
    """
    command.stamp(ctx.obj["alembic_config"], revision)


@cli.command()
@click.pass_context
def history(ctx):
    """
    List changeset scripts in chronological order.
    """
    command.history(ctx.obj["alembic_config"])


@cli.command()
@click.option(
    "--message",
    "-m",
    help="Message string to use with 'revision'",
)
@click.option(
    "--autogenerate",
    help="Populate revision script with candidate migration operations, based "
    "on comparison of database to model.",
    is_flag=True,
)
@click.option(
    "--sql",
    help="Don't emit SQL to database - dump to standard output/file instead. "
    "See docs on offline mode.",
)
@click.option(
    "--rev-id",
    help="Specify a hardcoded revision id instead of generating one",
)
@click.pass_context
def revision(ctx, message, autogenerate, sql, rev_id):
    """Create a new revision file."""
    command.revision(
        ctx.obj["alembic_config"],
        message=message,
        autogenerate=autogenerate,
        sql=sql,
        rev_id=rev_id,
    )


if __name__ == "__main__":
    cli(obj={})
