"""alter_token_value_index

Revision ID: b0d59fa7bac1
Revises: d111bfd5be7a
Create Date: 2022-04-27 11:07:11.788740

"""
import sqlalchemy as sa
from alembic import op

# flake8: noqa E501
# revision identifiers, used by Alembic.
revision = "b0d59fa7bac1"
down_revision = "d111bfd5be7a"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("access_token", "token_value", type_=sa.Text())
    op.alter_column("access_token", "based_on", type_=sa.Text())
    op.alter_column("access_token", "refresh_token", type_=sa.Text())

    op.alter_column("authorization_code", "token_value", type_=sa.Text())

    op.alter_column("refresh_token", "token_value", type_=sa.Text())
    op.alter_column("refresh_token", "based_on", type_=sa.Text())

    op.alter_column("id_token", "token_value", type_=sa.Text())
    op.alter_column("id_token", "based_on", type_=sa.Text())

    op.drop_constraint(op.f("access_token_token_value_key"), table_name="access_token")
    op.drop_index("ix_id_token_based_on", table_name="id_token")
    op.drop_constraint(op.f("id_token_token_value_key"), table_name="id_token")
    op.create_unique_constraint(None, "access_token", ["token_id"])
    op.drop_index("ix_authorization_code_token_id", table_name="authorization_code")
    op.create_unique_constraint(None, "authorization_code", ["token_id"])
    op.drop_index("ix_id_token_token_id", table_name="id_token")
    op.create_unique_constraint(None, "id_token", ["token_id"])
    op.drop_index("ix_refresh_token_token_id", table_name="refresh_token")
    op.create_unique_constraint(None, "refresh_token", ["token_id"])

    op.execute(
        sa.text(
            "CREATE UNIQUE INDEX ix_access_token_token_value ON access_token USING btree(CAST(md5(token_value) AS uuid))"
        )
    )
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS authorization_code_session_id RENAME to ix_authorization_code_session_id;"
        )
    )
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS refresh_token_session_id RENAME to ix_refresh_token_session_id;"
        )
    )
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS access_token_session_id RENAME to ix_access_token_session_id;"
        )
    )
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS id_token_session_id RENAME to ix_id_token_session_id;"
        )
    )


def downgrade():
    op.alter_column("access_token", "token_value", type_=sa.String(length=4096))
    op.alter_column("access_token", "based_on", type_=sa.String(length=4096))
    op.alter_column("access_token", "refresh_token", type_=sa.String(length=4096))

    op.alter_column("authorization_code", "token_value", type_=sa.String(length=4096))

    op.alter_column("refresh_token", "token_value", type_=sa.String(length=4096))
    op.alter_column("refresh_token", "based_on", type_=sa.String(length=4096))

    op.alter_column("id_token", "token_value", type_=sa.String(length=4096))
    op.alter_column("id_token", "based_on", type_=sa.String(length=4096))
    op.drop_index(op.f("ix_access_token_token_value"), table_name="access_token")
    op.drop_constraint(None, "refresh_token", type_="unique")
    op.create_index(
        "ix_refresh_token_token_id", "refresh_token", ["token_id"], unique=False
    )
    op.drop_constraint(None, "id_token", type_="unique")
    op.create_index("ix_id_token_token_id", "id_token", ["token_id"], unique=False)
    op.drop_constraint(None, "authorization_code", type_="unique")
    op.create_index(
        "ix_authorization_code_token_id",
        "authorization_code",
        ["token_id"],
        unique=False,
    )
    op.drop_constraint(None, "access_token", type_="unique")
    op.create_index(
        "ix_access_token_token_id", "access_token", ["token_id"], unique=False
    )

    op.create_index(
        op.f("access_token_token_value_key"),
        table_name="access_token",
        columns=["token_value"],
        unique=True,
    )
    op.create_index(
        op.f("id_token_token_value_key"),
        table_name="id_token",
        columns=["token_value"],
        unique=True,
    )
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS ix_authorization_code_session_id RENAME to authorization_code_session_id;"
        )
    )
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS ix_refresh_token_session_id RENAME to refresh_token_session_id;"
        )
    )
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS ix_access_token_session_id RENAME to access_token_session_id;"
        )
    )
    op.execute(
        sa.text(
            "ALTER INDEX IF EXISTS ix_id_token_session_id RENAME to id_token_session_id;"
        )
    )
