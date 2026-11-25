"""Migrate client claims

Revision ID: 40ac4890427a
Revises: 2fc1b973d394
Create Date: 2021-09-09 11:45:50.174683

"""
import json

from alembic import op
from sqlalchemy import orm

from satosa_oidc_frontend.models import Client

# revision identifiers, used by Alembic.
revision = "40ac4890427a"
down_revision = "2fc1b973d394"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    sql_session = orm.Session(bind=bind)

    for client in sql_session.query(Client).all():
        client_info = client.client_info
        if isinstance(client_info, str):
            client_info = json.loads(client_info)
        add_claims = {"always": {}}
        for module in ["userinfo", "id_token", "introspection", "access_token"]:
            key = f"{module}_claims"
            if key in client_info:
                add_claims["always"][module] = client_info[key]
        client_info["add_claims"] = add_claims
        client.client_info = client_info

    sql_session.commit()


def downgrade():
    pass
