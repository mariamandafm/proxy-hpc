"""session_migration

Revision ID: 2fc1b973d394
Revises: c980f1546ab5
Create Date: 2021-07-27 11:43:09.713316

"""
import json

from alembic import op
from sqlalchemy import JSON, Column, Integer, String, orm
from sqlalchemy.ext.declarative import declarative_base

# revision identifiers, used by Alembic.
revision = "2fc1b973d394"
down_revision = "c980f1546ab5"
branch_labels = None
depends_on = None

MIGRATION_STEP = 1000


Base = declarative_base()


class Session(Base):
    __tablename__ = "session"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True)
    session_id = Column(
        String(700),
        nullable=False,
        unique=True,
        index=True,
    )
    session_info = Column(JSON, nullable=True)


def compatible_session(session_info):
    type_mapping = {
        "usersessioninfo": "idpyoidc.server.session.info.UserSessionInfo",
        "clientsessioninfo": "idpyoidc.server.session.info.ClientSessionInfo",
        "grant": "idpyoidc.server.session.grant.Grant",
    }
    token_name_mapping = {
        "authorization_code": "AuthorizationCode",
        "access_token": "AccessToken",
        "refresh_token": "RefreshToken",
    }
    token_class_mapping = {
        "authorization_code": "idpyoidc.server.session.token.AuthorizationCode",
        "access_token": "idpyoidc.server.session.token.AccessToken",
        "refresh_token": "idpyoidc.server.session.token.RefreshToken",
    }

    if "type" not in session_info:
        print(f"No type field in session: {session_info}")
        raise ValueError()

    session_type = type_mapping[session_info.get("type").lower()]
    if session_type == "idpyoidc.server.session.grant.Grant":
        if "authentication_event" in session_info:
            session_info["authentication_event"] = {
                "idpyoidc.server.authn_event.AuthnEvent": session_info["authentication_event"]
            }
        if "authorization_request" in session_info:
            session_info["authorization_request"] = {
                "idpyoidc.message.oidc.AuthorizationRequest": dict(
                    session_info["authorization_request"],
                    code_challenge_method="plain",
                )
            }
        if "issued_token" in session_info:
            issued_tokens = []
            for token in session_info["issued_token"]:
                token = json.loads(token)
                token["token_class"] = token["type"]
                token["name"] = token_name_mapping[token["type"]]
                if token["type"] == "access_token":
                    token["token_type"] = "Bearer"
                issued_tokens.append({token_class_mapping[token["type"]]: token})
            session_info["issued_token"] = issued_tokens
        session_info["token_map"] = {
            "access_token": "idpyoidc.server.session.token.AccessToken",
            "authorization_code": "idpyoidc.server.session.token.AuthorizationCode",
            "id_token": "idpyoidc.server.session.token.IDToken",
            "refresh_token": "idpyoidc.server.session.token.RefreshToken",
        }
        session_info["extra"] = {}
    else:
        session_info["extra_args"] = {}

    return session_type, session_info


def upgrade():
    bind = op.get_bind()
    sql_session = orm.Session(bind=bind)
    count = sql_session.query(Session).count()
    i = 0

    while i <= count + MIGRATION_STEP:
        for session in (
            sql_session.query(Session).order_by(Session.id).slice(i, i + MIGRATION_STEP)
        ):
            session_info = json.loads(session.session_info)
            if not isinstance(session_info, list):
                session_type, session_info_dict = compatible_session(session_info)
                session.session_info = json.dumps([session_type, session_info_dict])

        sql_session.commit()
        i += MIGRATION_STEP


def downgrade():
    pass
