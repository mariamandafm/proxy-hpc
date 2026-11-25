from enum import Enum
from enum import unique
from functools import partial
from logging import getLogger as get_logger

from typing import Mapping
from typing import Optional
from typing import Sequence

from ldap3 import REUSABLE as LDAP_STRATEGY_REUSABLE
from ldap3 import Connection as LDAPConnection
from ldap3 import Server as LDAPServer
from ldap3.core.exceptions import LDAPException

from pydantic import Field

from requests_toolbelt.sessions import BaseUrlSession as create_http_client_session

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.config import AnyUrl
from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import SecretStr
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper

from coreaai_proxy_plugins.helpers.perun.rpc import RPCError
from coreaai_proxy_plugins.helpers.perun.rpc import get_ext_source
from coreaai_proxy_plugins.helpers.perun.rpc import create_ext_source
from coreaai_proxy_plugins.helpers.perun.rpc import prepare_candidate
from coreaai_proxy_plugins.helpers.perun.rpc import create_member
from coreaai_proxy_plugins.helpers.perun.rpc import set_membership_status
from coreaai_proxy_plugins.helpers.perun.rpc import get_user_attr
from coreaai_proxy_plugins.helpers.perun.rpc import get_ext_user_by_uniq_attr
from coreaai_proxy_plugins.helpers.perun.rpc import get_ext_user_by_login
from coreaai_proxy_plugins.helpers.perun.rpc import get_ext_user_attr
from coreaai_proxy_plugins.helpers.perun.rpc import set_ext_user_attrs


logger = ExtraLogger(get_logger(__name__))

DEFAULT_API_TIMEOUT = 3


class Error(SATOSAError):
    def __init__(self, message):
        super().__init__(message)
        self.error_context = message


class ConfigError(Error):
    pass


class AccountExistsError(Error):
    pass


@unique
class LookupStrategy(str, Enum):
    RPC_API = "rpc_api"
    LDAP_API = "ldap_api"


class Config(TableConfig):
    lookup_strategy: LookupStrategy
    vo_id: int
    vo_name: str
    cuid_external_provision: bool
    attr_internal_groups: str
    attr_internal_first_name: str
    attr_internal_last_name: str
    attr_internal_email: str
    attr_internal_epsa: str
    attr_internal_iuids: str
    attr_internal_cuid_preset: str
    attr_internal_cuid: str
    attr_perun_ues_iuids: str
    attr_perun_ues_epsa: str
    attr_perun_user_pref_email: str
    attr_perun_user_cuid: str
    attr_ldap_iuids: Optional[str] = None
    enable_extensions_activate_user: bool = False
    attr_perun_activate_user: str
    activate_user_value: str
    ldap_url: Optional[AnyUrl] = None
    ldap_bind_dn: Optional[str] = None
    ldap_bind_password: Optional[SecretStr] = None
    ldap_pool_size: Optional[int] = None
    ldap_pool_keepalive: Optional[int] = None
    ldap_client: Optional[LDAPConnection] = Field(default=None, exclude=True)
    ldap_search_base: Optional[str] = None
    api_base_url: AnyHttpUrl
    api_auth_user: str
    api_auth_password: SecretStr
    api_timeout: int = DEFAULT_API_TIMEOUT
    error_url: AnyHttpUrl


class CreateAccount(ResponseMicroService):
    """Provision a Perun account for a user who does not yet have one.

    Response microservice. It looks up an existing account by the user's IUIDs
    (via the Perun RPC API or LDAP, per ``lookup_strategy``); if none exists it
    creates the VO member (external source, candidate, membership) and records
    the IUIDs and ePSA on the Perun external user. On success it sets the
    internal CUID and group attributes on the response. If the account already
    exists it passes the request through unchanged; on any error it redirects to
    ``error_url``. Requests missing first name, last name, email or IUIDs are
    passed through untouched (a later plugin may handle registration).

    The configuration is a list of entries resolved per requester and issuer; a
    catch-all entry (empty/omitted ``requester`` and ``issuer``) is required as
    the fallback. ``ldap_api`` entries also require the ``ldap_*`` connection
    settings. Each entry accepts:

    Behaviour:
    - ``lookup_strategy`` — ``rpc_api`` or ``ldap_api``: how to look up an
      existing account
    - ``vo_id`` — Perun VO id the member is created in
    - ``vo_name`` — VO name, written to ``attr_internal_groups`` on success
    - ``cuid_external_provision`` — if true, the CUID must already be present in
      ``attr_internal_cuid_preset``; if it is missing the user is redirected to
      ``error_url``
    - ``enable_extensions_activate_user`` (default ``false``) — if true, set
      ``attr_perun_activate_user`` to ``activate_user_value`` on the new user
    - ``activate_user_value`` — value written when activating the user
    - ``error_url`` — URL to redirect to on failure

    Incoming (internal) attribute names:
    - ``attr_internal_first_name`` / ``attr_internal_last_name`` /
      ``attr_internal_email`` — the user's name and email
    - ``attr_internal_iuids`` — the IUIDs used for lookup and as the external
      login
    - ``attr_internal_epsa`` — eduPersonScopedAffiliation values
    - ``attr_internal_cuid_preset`` — a pre-set CUID (with
      ``cuid_external_provision``)

    Attributes set on the response:
    - ``attr_internal_cuid`` — set to the created/fetched CUID
    - ``attr_internal_groups`` — set to ``[vo_name]``

    Perun attribute names (targets in Perun):
    - ``attr_perun_ues_iuids`` / ``attr_perun_ues_epsa`` — external-user IUIDs
      and ePSA
    - ``attr_perun_user_pref_email`` — user preferred email
    - ``attr_perun_user_cuid`` — user CUID
    - ``attr_perun_activate_user`` — user activation attribute

    LDAP connection (``ldap_api`` strategy):
    - ``ldap_url`` / ``ldap_bind_dn`` / ``ldap_bind_password`` — server and bind
      credentials
    - ``ldap_pool_size`` / ``ldap_pool_keepalive`` — connection pool settings
    - ``ldap_search_base`` — search base DN
    - ``attr_ldap_iuids`` — LDAP attribute searched for the IUIDs
    (``ldap_client`` is built internally and must not be set in the config.)

    Perun RPC API connection:
    - ``api_base_url`` — RPC API base URL
    - ``api_auth_user`` / ``api_auth_password`` — HTTP Basic credentials
    - ``api_timeout`` — request timeout in seconds (default 3)
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        ldap_connections: dict[tuple, LDAPConnection] = {}
        for c in config:
            if (
                c.get("skip")
                or c.get("lookup_strategy") != LookupStrategy.LDAP_API
            ):
                continue

            key = (
                c["ldap_url"],
                c["ldap_bind_dn"],
                c["ldap_bind_password"],
                c["ldap_pool_size"],
                c["ldap_pool_keepalive"],
            )
            try:
                ldap_connections[key] = ldap_connections.get(key) or LDAPConnection(
                    LDAPServer(c["ldap_url"]),
                    user=c["ldap_bind_dn"],
                    password=c["ldap_bind_password"],
                    pool_size=c["ldap_pool_size"],
                    pool_keepalive=c["ldap_pool_keepalive"],
                    client_strategy=LDAP_STRATEGY_REUSABLE,
                    auto_bind=True,
                    read_only=True,
                    return_empty_attributes=True,
                    use_referral_cache=True,
                    auto_escape=True,
                    auto_encode=True,
                )
            except LDAPException as e:
                raise ConfigError("Failed to connect to LDAP") from e

        try:
            table_configs: Sequence[Config] = [
                Config(
                    lookup_strategy=c["lookup_strategy"],
                    vo_id=c["vo_id"],
                    vo_name=c["vo_name"],
                    cuid_external_provision=c["cuid_external_provision"],
                    attr_internal_groups=c["attr_internal_groups"],
                    attr_internal_first_name=c["attr_internal_first_name"],
                    attr_internal_last_name=c["attr_internal_last_name"],
                    attr_internal_email=c["attr_internal_email"],
                    attr_internal_epsa=c["attr_internal_epsa"],
                    attr_internal_iuids=c["attr_internal_iuids"],
                    attr_internal_cuid_preset=c["attr_internal_cuid_preset"],
                    attr_internal_cuid=c["attr_internal_cuid"],
                    attr_perun_ues_iuids=c["attr_perun_ues_iuids"],
                    attr_perun_ues_epsa=c["attr_perun_ues_epsa"],
                    attr_perun_user_pref_email=c["attr_perun_user_pref_email"],
                    attr_perun_user_cuid=c["attr_perun_user_cuid"],
                    attr_ldap_iuids=c.get("attr_ldap_iuids"),
                    ldap_url=c.get("ldap_url"),
                    ldap_bind_dn=c.get("ldap_bind_dn"),
                    ldap_bind_password=c.get("ldap_bind_password"),
                    ldap_pool_size=c.get("ldap_pool_size"),
                    ldap_pool_keepalive=c.get("ldap_pool_keepalive"),
                    # Only non-skip ldap_api entries have a connection (built
                    # above); rpc_api / skip entries resolve to None.
                    ldap_client=ldap_connections.get(
                        (
                            c.get("ldap_url"),
                            c.get("ldap_bind_dn"),
                            c.get("ldap_bind_password"),
                            c.get("ldap_pool_size"),
                            c.get("ldap_pool_keepalive"),
                        )
                    ),
                    ldap_search_base=c.get("ldap_search_base"),
                    enable_extensions_activate_user=c.get("enable_extensions_activate_user", False),
                    attr_perun_activate_user=c["attr_perun_activate_user"],
                    activate_user_value=c["activate_user_value"],
                    api_base_url=c["api_base_url"],
                    api_auth_user=c["api_auth_user"],
                    api_auth_password=c["api_auth_password"],
                    api_timeout=c.get("api_timeout", DEFAULT_API_TIMEOUT),
                    error_url=c["error_url"],
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise ConfigError("Invalid configuration") from e
        if not table_configs:
            raise ConfigError("Invalid configuration")
        hierarchial_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchial_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        issuer = data.auth_info.issuer
        email = next(iter(data.attributes.get(config.attr_internal_email) or []), None)
        first_name = next(
            iter(data.attributes.get(config.attr_internal_first_name) or []), None
        )
        last_name = next(
            iter(data.attributes.get(config.attr_internal_last_name) or []), None
        )
        epsa = data.attributes.get(config.attr_internal_epsa) or []
        iuids = data.attributes.get(config.attr_internal_iuids) or []
        cuid_preset = (data.attributes.get(config.attr_internal_cuid_preset) or [None])[0]

        # if the required attributes for registration are not found then skip processing.
        # the next plugin may raise an error, or redirect to manual registration.
        if not all(attrv for attrv in (first_name, last_name, email, iuids)):
            return super().process(context, data)

        if config.cuid_external_provision and not cuid_preset:
            error_context = {
                "message": "Failed to retrieve CUID",
                "cuid": cuid_preset,
                "attr_internal_cuid_preset": config.attr_internal_cuid_preset,
            }
            logger.error(error_context)
            return Redirect(config.error_url)

        http_client = create_http_client_session(base_url=config.api_base_url)
        http_client.request = partial(http_client.request, timeout=config.api_timeout)
        http_client.auth = (
            config.api_auth_user, config.api_auth_password.get_secret_value()
        )

        try:
            account = _process_create_account(
                config.lookup_strategy,
                config.ldap_client,
                config.ldap_search_base,
                config.attr_ldap_iuids,
                http_client,
                config.vo_id,
                issuer,
                email,
                first_name,
                last_name,
                epsa,
                iuids,
                cuid_preset,
                config.attr_perun_ues_epsa,
                config.attr_perun_ues_iuids,
                config.attr_perun_user_pref_email,
                config.attr_perun_user_cuid,
                config.enable_extensions_activate_user,
                config.attr_perun_activate_user,
                config.activate_user_value,
            )
        except AccountExistsError as e:
            logger.info(e)
            return super().process(context, data)
        except Error as e:
            logger.error(e)
            return Redirect(config.error_url)
        else:
            data.attributes[config.attr_internal_cuid] = [account["cuid"]]
            data.attributes[config.attr_internal_groups] = [config.vo_name]
            log_context = {
                "message": "Created account",
                "account": account,
            }
            logger.info(log_context)

        return super().process(context, data)


def _process_create_account(
    lookup_strategy: LookupStrategy,
    ldap_client,
    ldap_search_base,
    ldap_iuids_attribute,
    http_client,
    vo_id,
    issuer,
    email,
    first_name,
    last_name,
    epsa,
    iuids,
    cuid_preset,
    attr_perun_ues_epsa,
    attr_perun_ues_iuids,
    attr_perun_user_pref_email,
    attr_perun_user_cuid,
    enable_extensions_activate_user,
    attr_perun_activate_user,
    activate_user_value,
):
    # XXX to be replaced with match/case
    if lookup_strategy == LookupStrategy.LDAP_API:
        account = get_ldap_account_by_attribute(
            client=ldap_client,
            base=ldap_search_base,
            attribute=ldap_iuids_attribute,
            values=iuids,
        )
    elif lookup_strategy == LookupStrategy.RPC_API:
        account = get_account_by_iuids(
            client=http_client,
            attr_perun_ues_iuids=attr_perun_ues_iuids,
            iuids=iuids,
        )
    else:
        raise Error("No suitable lookup_strategy configured.")

    if account:
        error_context = {
            "message": "Account exists",
            "account": account,
        }
        raise AccountExistsError(error_context)

    account = create_account(
        client=http_client,
        vo_id=vo_id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        cuid=cuid_preset,
        ext_source_name=issuer,
        ext_user_login=iuids[0],
        attr_perun_user_pref_email=attr_perun_user_pref_email,
        attr_perun_user_cuid=attr_perun_user_cuid,
        enable_extensions_activate_user=enable_extensions_activate_user,
        attr_perun_activate_user=attr_perun_activate_user,
        activate_user_value=activate_user_value,
    )
    # XXX move to its own micro-service to always update the IUIDs
    #
    # XXX to add attributes we need to fetch the existing ones first
    # XXX there are none at this point - when we create a new account
    #
    # XXX to update the attributes we need the ext_user
    # XXX since there are no attributes yet, we cannot use get_ext_user_by_uniq_attr
    # XXX we have to use get_ext_user_by_login
    ext_user = get_ext_user_by_login_iuid(http_client, issuer, iuids[0])
    update_ext_user_attrs(
        http_client, ext_user["id"], attributes={
            attr_perun_ues_iuids: iuids, attr_perun_ues_epsa: epsa
        }
    )

    return account


def get_ldap_account_by_attribute(client, base, attribute, values):
    queries = [f"({attribute}={i})" for i in values]
    filter = f"""(|{"".join(queries)})"""
    try:
        response_id = client.search(base, filter, attributes=None)
    except LDAPException as e:
        error_context = {
            "message": "Failed to query LDAP",
            "filter": filter,
            "queries": queries,
        }
        raise Error(error_context) from e
    else:
        response, status = client.get_response(response_id)

    return response


def get_account_by_iuids(client, attr_perun_ues_iuids, iuids):
    def _get_account_by_identifier(identifier):
        try:
            return get_ext_user_by_uniq_attr(client, attr_perun_ues_iuids, identifier)
        except RPCError as e:
            return None

    # XXX parallelize
    accounts = map(_get_account_by_identifier, iuids)
    account = next((acc for acc in accounts if acc), None)
    return account


def create_fetch_ext_source(client, ext_source_name):
    try:
        ext_source = get_ext_source(client, ext_source_name)
    except RPCError as e:
        if e.error_context.get("name") != "ExtSourceNotExistsException":
            error_context = {
                "message": "Failed to fetch existing external source",
                "ext_source_name": ext_source_name,
            }
            raise Error(e.error_context) from e
    except Exception as e:
        error_context = {
            "message": "Failed to fetch external source",
            "ext_source_name": ext_source_name,
        }
        raise Error(error_context) from e
    else:
        return ext_source

    try:
        ext_source = create_ext_source(client, ext_source_name)
    except Exception as e:
        error_context = {
            "message": "Failed to create external source",
            "ext_source_name": ext_source_name,
        }
        raise Error(error_context) from e
    else:
        return ext_source


def create_account(
    client,
    vo_id,
    first_name,
    last_name,
    email,
    cuid,
    ext_source_name,
    ext_user_login,
    attr_perun_user_pref_email,
    attr_perun_user_cuid,
    enable_extensions_activate_user,
    attr_perun_activate_user,
    activate_user_value,
):
    try:
        ext_source = create_fetch_ext_source(client, ext_source_name)
        user_attrs = {
            attrn: attrv
            for attrn, attrv in (
                (attr_perun_user_pref_email, email),
                (attr_perun_user_cuid, cuid),
            )
            if attrv
        }

        if enable_extensions_activate_user:
            user_attrs[attr_perun_activate_user] = activate_user_value

        candidate = prepare_candidate(
            ext_user_login, ext_source, first_name, last_name, user_attrs=user_attrs
        )
        member = create_member(client, vo_id, candidate)
        _ = set_membership_status(client, member["id"])
        user_id = member["userId"]
        if not cuid:
            # trigger cuid creation
            cuid_obj = get_user_attr(client, user_id, attr_perun_user_cuid)
            cuid = cuid_obj.get("value")
    except Exception as e:
        error_context = {
            "message": "Failed to create account",
            "ext_source_name": ext_source_name,
            "vo_id": vo_id,
        }
        raise Error(error_context) from e
    else:
        return {
            "cuid": cuid,
            "member": member,
            "ext_source": ext_source,
        }


def get_ext_user_by_login_iuid(client, ext_source_name, iuid):
    try:
        ext_user = get_ext_user_by_login(client, ext_source_name, iuid)
    except Exception as e:
        error_context = {
            "message": "Failed to fetch external user by IUID",
            "ext_source_name": ext_source_name,
            "iuid": iuid,
        }
        raise Error(error_context) from e
    return ext_user


def update_ext_user_attrs(client, ext_user_id, attributes):
    try:
        attr_definitions = {
            attr_perun_name: get_ext_user_attr(client, ext_user_id, attr_perun_name)
            for attr_perun_name in attributes
            if attributes
        }
    except Exception as e:
        error_context = {
            "message": "Failed to fetch external user attribute definitions",
            "ext_user_id": ext_user_id,
            "attributes": attributes,
        }
        raise Error(error_context) from e

    attrs_with_values = {
        attr_perun_name: {
            **attr_definitions[attr_perun_name],
            "value": (
                attr_values
                if attr_definitions[attr_perun_name]["type"] == "java.util.ArrayList"
                else ";".join(attr_values)
                if attr_definitions[attr_perun_name]["friendlyName"] == "affiliation"
                else attr_values[0]
            ),
        }
        for attr_perun_name, attr_values in attributes.items()
        if attr_values
    }

    try:
        _ = set_ext_user_attrs(client, ext_user_id, attributes=attrs_with_values)
    except Exception as e:
        error_context = {
            "message": "Failed to update external user attributes",
            "ext_user_id": ext_user_id,
            "attributes": attributes,
            "attrs_with_values": attrs_with_values,
        }
        raise Error(error_context) from e
