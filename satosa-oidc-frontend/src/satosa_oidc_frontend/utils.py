import functools
import logging
import time
from hashlib import sha256
from typing import Any, Callable

from alembic import command, config, script
from alembic.config import Config
from alembic.runtime import migration
from cachetools import TTLCache, cached
from idpyoidc.server.client_authn import basic_authn
from idpyoidc.server.session.grant import TOKEN_MAP, qualified_name
from satosa.response import BadRequest
from satosa_oidc_frontend.alembic.utils import get_alembic_ini
from satosa_oidc_frontend.models import Client, has_table
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def check_current_head(engine):
    alembic_cfg = config.Config()
    alembic_cfg.set_main_option("script_location", "satosa_oidc_frontend:alembic")
    directory = script.ScriptDirectory.from_config(alembic_cfg)
    with engine.begin() as connection:
        context = migration.MigrationContext.configure(connection)
        return set(context.get_current_heads()) == set(directory.get_heads())


def create_db(engine, Base):
    target_metadata = Base.metadata
    if not all(not has_table(engine, table) for table in target_metadata.tables.keys()):
        # Tables already exist
        return

    db_uri = str(engine.url)
    if db_uri == "sqlite:///:memory:":
        # Hack: Do not try to create hashed index
        for index in target_metadata.tables["access_token"].indexes:
            if index.name == "ix_access_token_token_value":
                break
        target_metadata.tables["access_token"].indexes.remove(index)
        # Don't use alembic if it's an in memory db
        with engine.connect() as connection:
            Base.metadata.create_all(bind=connection)
        return

    alembic_cfg = Config(get_alembic_ini())
    alembic_cfg.set_main_option("script_location", "satosa_oidc_frontend:alembic")
    alembic_cfg.set_main_option("sqlalchemy.url", db_uri)
    with engine.connect() as connection:
        alembic_cfg.attributes["connection"] = connection
        command.upgrade(alembic_cfg, "head")


def get_token_from_header(header):
    header = header.split()
    if len(header) != 2:
        return

    if header[0] != "Bearer":
        return

    return header[1]


def token_class_to_str(token_class):
    return qualified_name(TOKEN_MAP.get(token_class))


def load_issued_token(token):
    cls = TOKEN_MAP.get(token.token_class)
    if not cls:
        raise ValueError(f"Unknown token class: {token.token_class}")

    token_instance = cls().load(token.token_value)
    return token_instance


def check_request_method(allowed_request_methods):
    def inner(fun):
        @functools.wraps(fun)
        def wrapper(self, context, *args, **kwargs):
            if (
                context.request_method
                and context.request_method not in allowed_request_methods
            ):
                return BadRequest("invalid_request")
            ret = fun(self, context, *args, **kwargs)
            return ret

        return wrapper

    return inner


def session_manager_dump(fun):
    @functools.wraps(fun)
    def wrapper(self, context, *args, **kwargs):
        request = context.request or {}
        request_authorization = context.request_authorization
        client_id = None
        if request and "client_id" in request:
            client_id = request["client_id"]
        elif context.request_method == "POST" and "access_token" in request:
            try:
                client = self._load_session_from_token(request["access_token"])[
                    "client"
                ]
                client_id = client.id
            except Exception:
                pass
        elif request_authorization:
            auth_info = request_authorization.split()
            if len(auth_info) != 2:
                pass
            elif auth_info[0] == "Basic":
                try:
                    auth = basic_authn(request_authorization)
                    client_id = auth["id"]
                except Exception:
                    pass
            elif auth_info[0] == "Bearer":
                try:
                    client = self._load_session_from_token(auth_info[1])["client"]
                    client_id = client.id
                except Exception:
                    pass

        if client_id:
            try:
                client_info = self.client_db[client_id]
                self.endpoint_context.cdb[client_id] = client_info
            except Exception:
                pass

        ret = fun(self, context, *args, **kwargs)

        self.store_sessions()
        self.endpoint_context.session_manager.flush()

        return ret

    return wrapper


def get_client(engine, client_id):
    with Session(engine) as session:
        q = session.query(Client)
        client = q.filter_by(client_id=client_id).first()
        if not client:
            return None, None
        return client.client_id, client.client_info


def create_client(
    engine,
    client_id,
    client_secret,
    redirect_uris=None,
    allowed_scopes=None,
    grant_types_supported=None,
    response_types=None,
    pkce_essential=None,
    revoke_refresh_on_issue=None,
    add_claims=None,
    claims_always_access_token=None,
    claims_always_id_token=None,
    claims_always_userinfo=None,
    claims_by_scope_access_token=None,
    claims_by_scope_id_token=None,
    claims_by_scope_userinfo=None,
    **kwargs,
):
    cid, _ = get_client(engine, client_id)
    if cid:
        raise ValueError(f"Client '{client_id}' already exists")
    client_info = {
        "client_secret": client_secret,
        **kwargs,
    }

    if redirect_uris:
        client_info["redirect_uris"] = []
        for uri in redirect_uris:
            if not isinstance(uri, list):
                client_info["redirect_uris"].append([uri, ""])
            else:
                client_info["redirect_uris"].append(uri)
    if allowed_scopes:
        client_info["allowed_scopes"] = allowed_scopes
    if grant_types_supported:
        client_info["grant_types_supported"] = grant_types_supported
    if response_types:
        client_info["response_types"] = response_types
    if pkce_essential:
        client_info["pkce_essential"] = pkce_essential
    if revoke_refresh_on_issue:
        client_info["revoke_refresh_on_issue"] = revoke_refresh_on_issue
    always = {}
    if claims_always_access_token:
        always["access_token"] = claims_always_access_token
    if claims_always_id_token:
        always["id_token"] = claims_always_id_token
    if claims_always_userinfo:
        always["userinfo"] = claims_always_userinfo
    by_scope = {}
    if claims_by_scope_access_token:
        by_scope["access_token"] = claims_by_scope_access_token
    if claims_by_scope_id_token:
        by_scope["id_token"] = claims_by_scope_id_token
    if claims_by_scope_userinfo:
        by_scope["userinfo"] = claims_by_scope_userinfo
    client_info["add_claims"] = {
        "always": always,
        "by_scope": by_scope,
    }
    with Session(engine) as session:
        session.add(Client(client_id=client_id, client_info=client_info))
        session.commit()
    return client_id, client_info


def modify_client(
    engine,
    client_id,
    add_allowed_scopes=None,
    add_claims_always_access_token=None,
    add_claims_always_id_token=None,
    add_claims_always_userinfo=None,
    add_grant_types_supported=None,
    add_redirect_uris=None,
    add_response_types=None,
    add_extra={},
    allowed_scopes=None,
    claims_always_access_token=None,
    claims_always_id_token=None,
    claims_always_userinfo=None,
    claims_by_scope_access_token=None,
    claims_by_scope_id_token=None,
    claims_by_scope_userinfo=None,
    client_secret=None,
    grant_types_supported=None,
    pkce_essential=None,
    redirect_uris=None,
    response_types=None,
    revoke_refresh_on_issue=None,
    remove_allowed_scopes=None,
    remove_claims_always_access_token=None,
    remove_claims_always_id_token=None,
    remove_claims_always_userinfo=None,
    remove_grant_types_supported=None,
    remove_redirect_uris=None,
    remove_response_types=None,
    remove_extra=[],
):
    """
    engine: An scqalchemy Engine
    client_id: The client_id
    add_allowed_scopes: A list of allowed scopes to be added in the client's
        allowed_scopes
    add_claims_always_access_token: A list of claims to be added in the client's
        claims that are returned in an access token
    add_claims_always_id_token: A list of claims to be added in the client's
        claims that are returned in an id token
    add_claims_always_userinfo: A list of claims to be added in the client's
        claims that are returned in the userinfo
    add_grant_types_supported: A list of grant types to be added in the client's
        grant_types_supported
    add_redirect_uris: A list of redirect uris to be added in the client's
        redirect_uris
    add_response_types: A list of response types to be added in the client's
        response_types
    add_extra: A dict of extra parameters that should be added to the client's
        metadata, this will overwrite any existing parameters with the same names
    allowed_scopes: A list of allowed scopes
    claims_always_access_token: A list of claims that are returned in an access token
    claims_always_id_token: A list of claims that are returned in an id token
    claims_always_userinfo: A list of claims that are returned in an userinfo
    claims_by_scope_access_token: Should the client's scopes be mapped to claims for
        the access token
    claims_by_scope_id_token: Should the client's scopes be mapped to claims for
        the id token
    claims_by_scope_userinfo: Should the client's scopes be mapped to claims for
        the userinfo
    client_secret: The client's secret
    grant_types_supported: A list of grant types
    pkce_essential: Bool for making PKCE mandatory
    redirect_uris: A list of redirect uris
    response_types: A list of response types
    revoke_refresh_on_issue: Bool for revoking refresh tokens when used
    remove_allowed_scopes: A list of allowed scopes to be removed from the client's
        allowed_scopes
    remove_claims_always_access_token: A list of claims to be removed from the client's
        claims that are returned in an access token
    remove_claims_always_id_token: A list of claims to be removed from the client's
        claims that are returned in an id token
    remove_claims_always_userinfo: A list of claims to be removed from the client's
        claims that are returned in the userinfo
    remove_grant_types_supported: A list of grant types to be removed from the client's
        grant_types_supported
    remove_redirect_uris: A list of redirect uris to be removed from the client's
        redirect_uris
    remove_response_types: A list of response types to be removed from the client's
        response_types
    remove_extra: A list of keys to remove from the clients metadata
    """
    # Add here any client params that start with add_ or remove_
    cid, client_info = get_client(engine, client_id)
    if cid is None:
        raise ValueError(f"Client '{client_id}' does not exist")

    client_info.update(add_extra)
    client_info = {k: v for k, v in client_info.items() if k not in remove_extra}

    if redirect_uris is not None:
        client_info["redirect_uris"] = redirect_uris
    if add_redirect_uris is not None:
        uris = set(
            tuple(uri) if isinstance(uri, list) else (uri, "")
            for uri in client_info["redirect_uris"]
        )
        uris = uris.union(
            set(
                tuple(uri) if isinstance(uri, list) else (uri, "")
                for uri in add_redirect_uris
            )
        )
        client_info["redirect_uris"] = [list(uri) for uri in uris]
    if remove_redirect_uris is not None:
        uris = set(
            tuple(uri) if isinstance(uri, list) else (uri, "")
            for uri in client_info["redirect_uris"]
        )
        uris = uris.difference(
            set(
                tuple(uri) if isinstance(uri, list) else (uri, "")
                for uri in remove_redirect_uris
            )
        )
        client_info["redirect_uris"] = [list(uri) for uri in uris]

    if allowed_scopes is not None:
        client_info["allowed_scopes"] = allowed_scopes
    if add_allowed_scopes is not None:
        uris = set(client_info["allowed_scopes"])
        uris = uris.union(set(add_allowed_scopes))
        client_info["allowed_scopes"] = list(uris)
    if remove_allowed_scopes is not None:
        uris = set(client_info["allowed_scopes"])
        uris = uris.difference(set(remove_allowed_scopes))
        client_info["allowed_scopes"] = list(uris)

    if claims_always_access_token is not None:
        client_info["claims_always_access_token"] = claims_always_access_token
    if add_claims_always_access_token is not None:
        uris = set(client_info["claims_always_access_token"])
        uris = uris.union(set(add_claims_always_access_token))
        client_info["claims_always_access_token"] = list(uris)
    if remove_claims_always_access_token is not None:
        uris = set(client_info["claims_always_access_token"])
        uris = uris.difference(set(remove_claims_always_access_token))
        client_info["claims_always_access_token"] = list(uris)

    if claims_always_id_token is not None:
        client_info["claims_always_id_token"] = claims_always_id_token
    if add_claims_always_id_token is not None:
        uris = set(client_info["claims_always_id_token"])
        uris = uris.union(set(add_claims_always_id_token))
        client_info["claims_always_id_token"] = list(uris)
    if remove_claims_always_id_token is not None:
        uris = set(client_info["claims_always_id_token"])
        uris = uris.difference(set(remove_claims_always_id_token))
        client_info["claims_always_id_token"] = list(uris)

    if claims_always_userinfo is not None:
        client_info["claims_always_userinfo"] = claims_always_userinfo
    if add_claims_always_userinfo is not None:
        uris = set(client_info["claims_always_userinfo"])
        uris = uris.union(set(add_claims_always_userinfo))
        client_info["claims_always_userinfo"] = list(uris)
    if remove_claims_always_userinfo is not None:
        uris = set(client_info["claims_always_userinfo"])
        uris = uris.difference(set(remove_claims_always_userinfo))
        client_info["claims_always_userinfo"] = list(uris)

    if grant_types_supported is not None:
        client_info["grant_types_supported"] = grant_types_supported
    if add_grant_types_supported is not None:
        uris = set(client_info["grant_types_supported"])
        uris = uris.union(set(add_grant_types_supported))
        client_info["grant_types_supported"] = list(uris)
    if remove_grant_types_supported is not None:
        uris = set(client_info["grant_types_supported"])
        uris = uris.difference(set(remove_grant_types_supported))
        client_info["grant_types_supported"] = list(uris)

    if response_types is not None:
        client_info["response_types"] = response_types
    if add_response_types is not None:
        uris = set(client_info["response_types"])
        uris = uris.union(set(add_response_types))
        client_info["response_types"] = list(uris)
    if remove_response_types is not None:
        uris = set(client_info["response_types"])
        uris = uris.difference(set(remove_response_types))
        client_info["response_types"] = list(uris)

    if client_secret is not None:
        client_info["client_secret"] = client_secret

    with Session(engine) as session:
        session.query(Client).filter(Client.client_id == client_id).update(
            {"client_info": client_info}
        )
        session.commit()
    return client_id, client_info


def delete_client(engine, client_id):
    with Session(engine) as session:
        q = session.query(Client)
        res = q.filter_by(client_id=client_id).delete()
        session.commit()
    return res


def get_all_clients(engine):
    with Session(engine) as session:
        q = session.query(Client)
        return q.all()


def secured_ttl_cache(
    maxsize: int = 128, ttl: int = 600
) -> Callable[[Callable], Callable]:
    """
    A decorator to cache function results using hashed args/kwargs for security, with ttl.

    Args:
        maxsize: Maximum cache size (see `functools.lru_cache`).
        ttl: Time to live for cached results (in seconds).
    """

    def decorator(func: Callable) -> Callable:
        cache_instance = TTLCache(maxsize=maxsize, ttl=ttl)

        def _generate_cache_key(*args: Any, **kwargs: Any) -> str:
            key_data = (
                ":".join(map(str, args))
                + ":"
                + ":".join(f"{k}={v}" for k, v in kwargs.items())
            )
            return sha256(key_data.encode("utf-8")).hexdigest()

        @cached(
            cache_instance,
            key=lambda *args, **kwargs: _generate_cache_key(*args, **kwargs),
        )
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        return wrapper

    return decorator
