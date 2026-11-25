import logging
import os
from logging.config import fileConfig

# import alembic.command
from alembic import context

# from alembic.runtime import migration
from sqlalchemy import create_engine

from satosa_oidc_frontend.models import Base

target_metadata = Base.metadata

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

if config.attributes.get("configure_logger", False):
    fileConfig(config.config_file_name)

logger = logging.getLogger(__name__)


def get_url():
    url = config.get_main_option("sqlalchemy.url", None)
    if not url:
        url = os.environ.get("SATOSA_OIDC_FRONTEND_DATABASE_URL", "sqlite:///app.db")
    return url


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """

    url = get_url()

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online(connectable=None):
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # connectable = engine_from_config(
    #     config.get_section(config.config_ini_section),
    #     prefix="sqlalchemy.",
    #     poolclass=pool.NullPool,
    # )

    if not connectable:
        url = get_url()
        connectable = create_engine(url)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
