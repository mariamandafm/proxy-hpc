"""Migrate add grant type

Revision ID: d111bfd5be7a
Revises: a00e97de1004
Create Date: 2022-01-26 19:04:30.504075

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d111bfd5be7a"
down_revision = "a00e97de1004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "grant_session",
        sa.Column(
            "grant_type", sa.String(length=700), nullable=True, server_default="grant"
        ),
    )


def downgrade():
    op.drop_column("grant_session", "grant_type")
