"""Migrate tokens

Revision ID: 2c09262e65b5
Revises: a00e97de1004
Create Date: 2021-11-17 19:41:41.257144

"""
import json
import os

import click
from idpyoidc.server.constant import DIVIDER
from idpyoidc.server.session.grant import Grant
from idpyoidc.server.session.info import ClientSessionInfo, UserSessionInfo
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Index,
    Integer,
    String,
    create_engine,
    exists,
    false,
    or_,
    select,
)
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import Session as orm_session

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


class UserSession(Base):
    __tablename__ = "user_session"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True)
    user_id = Column(
        String(700),
        nullable=False,
        unique=True,
        index=True,
    )
    revoked = Column(Boolean)


class ClientSession(Base):
    __tablename__ = "client_session"
    __table_args__ = (
        Index("client_session_id", "user_id", "client_id", unique=True),
        {"extend_existing": True},
    )
    id = Column(Integer, primary_key=True)
    client_id = Column(String(700), nullable=False, index=True)
    user_id = Column(String(700), nullable=False)
    revoked = Column(Boolean)


class GrantSession(Base):
    __tablename__ = "grant_session"
    __table_args__ = (
        Index("grant_session_id", "user_id", "client_id", "grant_id", unique=True),
        {"extend_existing": True},
    )
    id = Column(Integer, primary_key=True)
    client_id = Column(String(700), nullable=False, index=True)
    user_id = Column(String(700), nullable=False)
    grant_id = Column(String(700), nullable=False)
    grant_info = Column(JSON, nullable=True)
    revoked = Column(Boolean)


class TokenMixin:
    id = Column(Integer, primary_key=True)
    token_id = Column(
        String(700),
        nullable=False,
        unique=True,
        index=True,
    )
    token_value = Column(String(4096), nullable=False, unique=True, index=True)
    token_args = Column(JSON, nullable=True)
    grant_id = Column(String(700), nullable=False)
    client_id = Column(String(700), nullable=False, index=True)
    user_id = Column(String(700), nullable=False)
    scope = Column(JSON, nullable=True)
    revoked = Column(Boolean)
    expires_at = Column(Integer)

    @declared_attr
    def __tablename__(cls):
        if not cls.name:
            raise NotImplementedError
        return cls.name

    @declared_attr
    def __table_args__(cls):
        if not cls.name:
            raise NotImplementedError
        return (
            Index(
                f"{cls.name}_session_id",
                "user_id",
                "client_id",
                "grant_id",
                unique=True,
            ),
            {"extend_existing": True},
        )


class AuthorizationCode(TokenMixin, Base):
    name = "authorization_code"


class AccessToken(TokenMixin, Base):
    name = "access_token"
    based_on = Column(String(4096), nullable=True, index=True)
    # The refresh token that was created along this access token,
    # this is used to revoke access tokens when the refresh token is used
    # (if configured that way)
    refresh_token = Column(String(4096), nullable=True, index=True)
    token_type = Column(String(700), nullable=False)


class IDToken(TokenMixin, Base):
    name = "id_token"
    based_on = Column(String(4096), nullable=True, index=True)


class RefreshToken(TokenMixin, Base):
    name = "refresh_token"
    based_on = Column(String(4096), nullable=True, index=True)


token_class_to_model = {
    "authorization_code": AuthorizationCode,
    "access_token": AccessToken,
    "id_token": IDToken,
    "refresh_token": RefreshToken,
}


def serialize_token_to_dict(token, user_id, client_id, grant_id, scope=None):
    token_args = token.dump()
    token_value = token_args.pop("value")
    if not scope:
        scope = token.scope

    serialized = dict(
        token_id=token.id,
        token_value=token_value,
        token_args=token_args,
        grant_id=grant_id,
        client_id=client_id,
        user_id=user_id,
        scope=scope,
        revoked=token.revoked,
        expires_at=token.expires_at,
    )
    if token.token_class == "access_token":
        serialized["token_type"] = token_args["token_type"]
    if token.token_class != "authorization_code":
        if "based_on" in token_args:
            serialized["based_on"] = token_args.get("based_on")
    return serialized


def serialize_token(token, user_id, client_id, grant_id, scope=None):
    serialized = serialize_token_to_dict(
        token, user_id, client_id, grant_id, scope=scope
    )
    token_cls = token_class_to_model[token.token_class]

    return token_cls(**serialized)


def serialize_user_session_to_dict(user):
    return dict(
        user_id=user.user_id,
        revoked=user.revoked,
    )


def serialize_user_session(user):
    return UserSession(**serialize_user_session_to_dict(user))


def serialize_client_session_to_dict(client, user_id):
    return dict(
        user_id=user_id,
        client_id=client.client_id,
        revoked=client.revoked,
    )


def serialize_client_session(client, user_id):
    return ClientSession(**serialize_client_session_to_dict(client, user_id))


def serialize_grant_session_to_dict(grant, user_id, client_id):
    return dict(
        user_id=user_id,
        client_id=client_id,
        grant_id=grant.id,
        grant_info=grant.dump(),
    )


def serialize_grant_session(grant, user_id, client_id):
    return GrantSession(**serialize_grant_session_to_dict(grant, user_id, client_id))


def user_session_exists(user_id, db_session):
    return db_session.query(
        select(UserSession).where(UserSession.user_id == user_id).exists()
    ).scalar()


def client_session_exists(user_id, client_id, db_session):
    return db_session.query(
        select(ClientSession)
        .where(
            ClientSession.user_id == user_id,
            ClientSession.client_id == client_id,
        )
        .exists()
    ).scalar()


def grant_session_exists(user_id, client_id, grant_id, db_session):
    return db_session.query(
        select(GrantSession)
        .where(
            GrantSession.user_id == user_id,
            GrantSession.client_id == client_id,
            GrantSession.grant_id == grant_id,
        )
        .exists()
    ).scalar()


def token_exists(token, db_session):
    token_cls = token_class_to_model[token.token_class]
    return db_session.query(
        select(token_cls)
        .where(
            token_cls.token_id == token.id,
        )
        .exists()
    ).scalar()


def unpack_session_key(session_id):
    sids = session_id.split(DIVIDER)
    client_id = grant_id = None
    if len(sids) == 1:
        user_id = sids[0]
    elif len(sids) == 2:
        user_id, client_id = sids
    elif len(sids) == 3:
        user_id, client_id, grant_id = sids
    else:
        raise ValueError("Unknown sid format")
    return user_id, client_id, grant_id


def load_grant(session_info, grant_id):
    grant = Grant().load(session_info)
    grant.id = grant_id
    tokens = grant.issued_token
    grant.issued_token = []
    return grant, tokens


@click.command()
@click.option(
    "--db-uri",
    type=str,
    help="A db_uri to use in order to connect to the database, defaults to env "
    "var 'SATOSA_OIDC_FRONTEND_DB_URI'",
    default=lambda: os.environ.get("SATOSA_OIDC_FRONTEND_DB_URI", ""),
)
@click.option(
    "--step",
    type=int,
    help="How many sessions to fetch from the database in each step",
    default=1000,
)
@click.option(
    "--migrate-all",
    is_flag=True,
    help="Migrate all sessions, even if they have already been migrated, "
    "this flag should be used when more tokens were added to some already migrated "
    "sessions.",
)
@click.option(
    "--no-update",
    is_flag=True,
    help="If a session or a token already exists at the target table, don't update it. "
    "This option should be used in conjuction with `--migrate-all`",
)
def migrate(db_uri, step, migrate_all, no_update):
    """
    Run this script after revision a00e97de1004 to migrate the old sessions into the new
    schema
    """
    engine = create_engine(db_uri)
    sql_session = orm_session(engine)
    stmt = false()
    if not migrate_all:
        stmt = exists().where(Session.session_id == UserSession.user_id)
        stmt = or_(
            stmt,
            exists().where(
                Session.session_id
                == (ClientSession.user_id + DIVIDER + ClientSession.client_id)
            ),
        )
        stmt = or_(
            stmt,
            exists().where(
                Session.session_id
                == (
                    GrantSession.user_id
                    + DIVIDER
                    + GrantSession.client_id
                    + DIVIDER
                    + GrantSession.grant_id
                )
            ),
        )
    count = sql_session.query(Session).filter(~stmt).count()
    print(f"Migrating {count} sessions")
    i = 0

    while i <= count + step:
        users_to_store = []
        users_to_update = []
        clients_to_store = []
        clients_to_update = []
        grants_to_store = []
        grants_to_update = []
        tokens_to_store = []
        tokens_to_update = {}
        if migrate_all:
            session_slice = (
                sql_session.query(Session).order_by(Session.id).slice(i, i + step)
            )
        else:
            # This query will not return the ones we have already migrated
            session_slice = (
                sql_session.query(Session)
                .filter(~stmt)
                .order_by(Session.id)
                .slice(0, step)
            )
        for session in session_slice:
            session_info = session.session_info
            if isinstance(session_info, str):
                session_info = json.loads(session_info)
            session_type, session_info_dict = session_info
            user_id, client_id, grant_id = unpack_session_key(session.session_id)
            if session_type == "idpyoidc.server.session.info.UserSessionInfo":
                if user_id is None or client_id is not None or grant_id is not None:
                    continue
                user_session = UserSessionInfo(
                    user_id=user_id, revoked=session_info_dict.get("revoked", False)
                )
                if not user_session_exists(user_id, sql_session):
                    users_to_store.append(serialize_user_session(user_session))
                elif not no_update and migrate_all:
                    users_to_update.append(serialize_user_session_to_dict(user_session))
            elif session_type == "idpyoidc.server.session.info.ClientSessionInfo":
                if user_id is None or client_id is None or grant_id is not None:
                    continue
                client_session = ClientSessionInfo(
                    client_id=client_id, revoked=session_info_dict.get("revoked", False)
                )
                if not client_session_exists(user_id, client_id, sql_session):
                    clients_to_store.append(
                        serialize_client_session(client_session, user_id)
                    )
                elif not no_update and migrate_all:
                    clients_to_update.append(
                        serialize_client_session_to_dict(client_session, user_id)
                    )

            elif session_type == "idpyoidc.server.session.grant.Grant":
                if user_id is None or client_id is None or grant_id is None:
                    continue

                grant, tokens = load_grant(session_info_dict, grant_id)
                for token in tokens:
                    if not token_exists(token, sql_session):
                        tokens_to_store.append(
                            serialize_token(
                                token,
                                user_id,
                                client_id,
                                grant_id,
                                scope=grant.find_scope(token),
                            )
                        )
                    elif not no_update and migrate_all:
                        if token.token_class not in tokens_to_update:
                            tokens_to_update[token.token_class] = []
                        tokens_to_update[token.token_class].append(
                            serialize_token_to_dict(
                                token,
                                user_id,
                                client_id,
                                grant_id,
                                scope=grant.find_scope(token),
                            )
                        )
                if not grant_session_exists(user_id, client_id, grant_id, sql_session):
                    grants_to_store.append(
                        serialize_grant_session(grant, user_id, client_id)
                    )
                elif not no_update and migrate_all:
                    grants_to_update.append(
                        serialize_grant_session_to_dict(grant, user_id, client_id)
                    )
        if users_to_store:
            print(f"Writing {len(users_to_store)} users to database")
            sql_session.add_all(users_to_store)
        if users_to_update:
            print(f"Updating {len(users_to_update)} users")
            for user in users_to_update:
                sql_session.query(UserSession).filter(
                    UserSession.user_id == user["user_id"],
                ).update(user)
        if clients_to_store:
            print(f"Writing {len(clients_to_store)} clients to database")
            sql_session.add_all(clients_to_store)
        if clients_to_update:
            print(f"Updating {len(clients_to_update)} clients")
            for client in clients_to_update:
                sql_session.query(ClientSession).filter(
                    ClientSession.user_id == client["user_id"],
                    ClientSession.client_id == client["client_id"],
                ).update(client)
        if grants_to_store:
            print(f"Writing {len(grants_to_store)} grants to database")
            sql_session.add_all(grants_to_store)
        if grants_to_update:
            print(f"Updating {len(grants_to_update)} grants")
            for grant in grants_to_update:
                sql_session.query(GrantSession).filter(
                    GrantSession.user_id == grant["user_id"],
                    GrantSession.client_id == grant["client_id"],
                    GrantSession.grant_id == grant["grant_id"],
                ).update(grant)
        if tokens_to_store:
            print(f"Writing {len(tokens_to_store)} tokens to database")
            sql_session.add_all(tokens_to_store)
        for token_cls, tokens in tokens_to_update.items():
            print(f"Updating {len(tokens)} {token_cls}")
            cls = token_class_to_model[token_cls]
            for token in tokens:
                sql_session.query(cls).filter(
                    cls.token_id == token["token_id"],
                ).update(token)

        sql_session.commit()
        i += step
