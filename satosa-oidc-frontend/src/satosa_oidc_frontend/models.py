from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Index,
    Integer,
    String,
    Text,
    func,
    inspect,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base, declared_attr

Base = declarative_base()


class Client(Base):
    __tablename__ = "client"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True)
    client_id = Column(
        String(700),
        nullable=False,
        unique=True,
        index=True,
    )
    client_info = Column(JSON, nullable=True)


class User(Base):
    __tablename__ = "user"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True)
    user_id = Column(
        String(700),
        nullable=False,
        unique=True,
        index=True,
    )
    user_info = Column(JSON, nullable=True)


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
    grant_type = Column(String(700), nullable=True, server_default="grant")
    grant_info = Column(JSON, nullable=True)
    revoked = Column(Boolean)


class TokenMixin:
    id = Column(Integer, primary_key=True)
    token_id = Column(String(700), nullable=False, unique=True)
    token_value = Column(Text, nullable=False, unique=True)
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
                f"ix_{cls.name}_session_id",
                "user_id",
                "client_id",
                "grant_id",
            ),
            {"extend_existing": True},
        )


class AuthorizationCode(TokenMixin, Base):
    name = "authorization_code"


class AccessToken(TokenMixin, Base):
    name = "access_token"
    based_on = Column(Text, nullable=True, index=True)
    token_value = Column(Text, nullable=False)
    # The refresh token that was created along this access token,
    # this is used to revoke access tokens when the refresh token is used
    # (if configured that way)
    refresh_token = Column(Text, nullable=True, index=True)
    token_type = Column(String(700), nullable=False)

    @declared_attr
    def __table_args__(cls):
        if not cls.name:
            raise NotImplementedError
        return (
            Index(
                f"ix_{cls.name}_session_id",
                "user_id",
                "client_id",
                "grant_id",
            ),
            Index(
                f"ix_{cls.name}_token_value",
                func.cast(func.md5("token_value"), UUID),
                unique=True,
            ),
            {"extend_existing": True},
        )


class IDToken(TokenMixin, Base):
    name = "id_token"
    token_value = Column(Text, nullable=False)
    based_on = Column(Text, nullable=True)


class RefreshToken(TokenMixin, Base):
    name = "refresh_token"
    based_on = Column(Text, nullable=True, index=True)


def has_table(engine, table_name):
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    return table_name in tables
