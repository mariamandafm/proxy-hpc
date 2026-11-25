import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from functools import cached_property
from logging import getLogger
from typing import (
    Mapping,
    Sequence,
    Any,
    get_type_hints,
    Type,
    TypeVar,
    Callable,
    Optional,
)

from jwt import PyJWKSet
from pydantic import Field, HttpUrl, validator, BaseModel
from requests import Session
from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.config import (
    Issuer,
    Requester,
    TableConfig,
    resolve_config_wrapper,
    get_config_from_hierarchy,
)
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config
from coreaai_proxy_plugins.helpers.iamapi import (
    IamApiClient,
    IamApiContext,
    LookupResult,
    UpsertIdentityParams,
    LookupParams,
    RegisterAccountParams,
    IamApiRole,
    IamApiConfig,
    AcceptedPolicy,
    AccountProfile,
    LookupIdentity,
    use_context,
)
from coreaai_proxy_plugins.helpers.jwt import validate_signing_keys, sign_token
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper
from coreaai_proxy_plugins.helpers.sessions import SessionStoreConfig

_logger = ExtraLogger(getLogger(__name__))


class PluginConfig(TableConfig):
    cuid_attribute: str
    iuid_attribute: str
    claims_mapping: dict[str, str]
    profile_mapping: dict[str, str]
    error_url: HttpUrl
    iam_api_url: HttpUrl
    iam_api_request_timeout_seconds: int = 5
    signing_keys: PyJWKSet = Field(exclude=True)
    jwt_audience: str
    token_lifetime_seconds: int = 10 * 60  # 10 minutes
    # Set defaults for missing attributes
    default_attributes: Optional[dict[str, Any]] = Field(default_factory=dict)
    # Check jwks have at least one usable signing key
    _validate_jwks = validator("signing_keys", allow_reuse=True, pre=True)(
        validate_signing_keys
    )


class IamUserRegistrationError(SATOSAError):
    """Generic error."""


class IamUserRegistration(ResponseMicroService):
    """
    Example configuration:

    ```
    module: satosa.micro_services.iam_user_registration.IamUserRegistration
    name: IamUserRegistration
    config:
      - # The internal attribute that holds the CUID of the user
        cuid_attribute:

        # The internal attribute that holds the IUIDs of the user
        iuid_attribute:

        # Mapping of internal attributes to IAM attributes to register an identity
        claims_mapping:
          name: name_internal_attr
          family_name: family_name_internal_attr
          email: email_internal_attr

        # Mapping of internal attributes to IAM attributes to register an account
        profile_mapping:
          first_name: first_name_internal_attr
          last_name: last_name_internal_attr
          email: email_internal_attr

        # The API endpoint used to lookup identities in the IAM backend
        iam_api_url:

        # Number of seconds before the HTTP request to the API times out.
        # Default is 3
        iam_api_request_timeout_seconds: 10

        # The satosa JWKS used for signing the JWT
        signing_keys: {"keys": []}

        # The audience claim to use when signing the JWT (typically the client_id of the IAM API)
        jwt_audience: "app-12345"

        # The lifetime (in seconds) of token generated for external api calls
        # Default is 600 (10 minutes)
        token_lifetime_seconds:

        # The page where user will be redirected in case of error
        error_url:
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)
        hierarchical_config = restructure_table_config_to_hierarchical_config(
            [PluginConfig.parse_obj(c) for c in config]
        )
        self.config = hierarchical_config
        self.session_store = SessionStoreConfig()

    @logging_wrapper(_logger)
    @resolve_config_wrapper(_logger)
    def process(
        self, context: Context, internal_data: InternalData, config: PluginConfig
    ):
        if not config or config.skip:
            return super().process(context, internal_data)
        account_info = resolve_account_info(internal_data, config, readonly=False)
        internal_data.attributes |= account_info_attributes(account_info) | {
            "iam_context_id": [
                f"{datetime.now(timezone.utc).timestamp()}:{uuid.uuid4().hex}"
            ]
        }
        ctx = IamApiContext(
            account_info=account_info,
            resume_endpoint=self.endpoint,
        )
        if a := account_info.primary_account:
            ctx.account_owner_api_client = create_account_api_client(
                config, a.account_uid
            )
        with use_context(ctx):
            return super().process(context, internal_data)

    @cached_property
    def endpoint(self) -> str:
        return f"iam-connector/{self.name}/resume"

    def register_endpoints(self) -> list[tuple[str, Callable]]:
        url_map = [(f"^{self.endpoint}", self.handle_resume)]
        return url_map

    def handle_resume(self, context: Context):
        context, internal_data = self.session_store.resume_session(context)
        config = get_config_from_hierarchy(
            self.config,
            requester=Requester(internal_data.requester),
            issuer=Issuer(internal_data.auth_info.issuer),
        )
        account_info = resolve_account_info(internal_data, config, True)
        internal_data.attributes |= account_info_attributes(account_info)
        ctx = IamApiContext(
            account_info=account_info,
            resume_endpoint=self.endpoint,
        )
        if a := account_info.primary_account:
            ctx.account_owner_api_client = create_account_api_client(
                config, account_uid=a.account_uid
            )
        with use_context(ctx):
            return super().process(context, internal_data)


def account_info_attributes(account_info: LookupResult) -> dict[str, list[str]]:
    attrs = dict[str, list[str]]()
    for account in account_info.accounts or []:
        for k, v in account.jwt_claims.items():
            values = attrs.setdefault(k, [])
            if v not in values:
                values.append(v)
    return attrs


def create_account_api_client(
    config: PluginConfig, account_uid: str, cuid: Optional[str] = None
) -> IamApiClient:
    # Register or update account on behalf of the user
    account_token = sign_token(
        config.signing_keys,
        cuid or account_uid,
        IamApiRole.IAM_ACCOUNT_OWNER.claims(account_uid=account_uid)
        | {"aud": config.jwt_audience},
        config.token_lifetime_seconds,
    )
    session = Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {account_token}",
        }
    )
    api = IamApiClient(
        config=IamApiConfig(
            base_url=config.iam_api_url,
        ),
        session=session,
    )
    return api


def create_proxy_api_client(config: PluginConfig):
    # Initialize HTTP client
    proxy_token = sign_token(
        config.signing_keys,
        "service_account",
        IamApiRole.IAM_PROXY_SERVICE.claims() | {"aud": config.jwt_audience},
        config.token_lifetime_seconds,
    )
    session = Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {proxy_token}",
        }
    )
    api = IamApiClient(
        config=IamApiConfig(
            base_url=config.iam_api_url,
        ),
        session=session,
    )
    return api


def policies_from_attributes(attr: Mapping[str, Any]):
    policies = _remap(
        {
            "acceptable_usage_policy": "policy_aup",
            "terms_of_use": "policy_tou",
            "privacy_policy": "policy_privacy",
        },
        attr,
    )
    result = list[AcceptedPolicy]()
    for policy_type, policy_urls in policies.items():
        if not policy_urls:
            continue
        elif isinstance(policy_urls, str):
            result.append(
                AcceptedPolicy.parse_obj(
                    dict(
                        policy_type=policy_type,
                        policy_url=policy_urls,
                    )
                )
            )
        elif isinstance(policy_urls, list):
            if not all(isinstance(u, str) for u in policy_urls):
                raise ValueError(
                    f"Invalid policy URLs for {policy_type}: {policy_urls}"
                )
            for policy_url in policy_urls:
                result.append(
                    AcceptedPolicy.parse_obj(
                        dict(
                            policy_type=policy_type,
                            policy_url=policy_url,
                        )
                    )
                )
        else:
            raise ValueError(f"Invalid policy URLs for {policy_type}: {policy_urls}")
    return result


def _remap_first(
    mapping: Mapping[str, str],
    attrs: Mapping[str, Any],
) -> Any:
    return _remap(mapping, attrs, lambda _from, _to, v: _first(v))


def _remap(
    mapping: Mapping[str, str],
    attrs: Mapping[str, Any],
    fn: Optional[Callable[[str, str, Any], Any]] = None,
) -> Any:
    if fn is None:
        fn = _default_remap
    return dict(
        (to_key, fn(from_key, to_key, attrs.get(from_key)))
        for to_key, from_key in mapping.items()
    )


def _default_remap(_from, _to, value):
    return value


Model = TypeVar("Model", bound=BaseModel)


def _remap_as_model(
    cls: Type[Model], mapping: Mapping[str, str], attrs: Mapping[str, Any]
) -> Model:
    """
    Use typing hints from a model class to infer correct value mapping
    """
    hints = get_type_hints(cls)

    def remap(dst: str, src: str):
        """
        Resolve to first item if value is a list and model does not expect a list-like type
        """
        value = attrs.get(src)
        if isinstance(value, (list, tuple, set)):
            hint = hints.get(dst)
            hint = hint.__origin__ if hint and hasattr(hint, "__origin__") else hint
            if hint not in (list, tuple, set):
                return dst, next(iter(value), None)
        return dst, value

    values = dict(remap(dst, src) for dst, src in mapping.items() if dst in hints)
    return cls.parse_obj(values)


def _first(value):
    if value is None:
        return None
    elif isinstance(value, str):
        return value
    elif isinstance(value, Iterable):
        return next(iter(value), None)
    else:
        return value


def _with_defaults(defaults: dict[str, Any], attributes: dict[str, Any]):
    if not defaults:
        return attributes, set[str]()
    if keys := set(defaults) - set(attributes):
        return defaults | attributes, keys
    return attributes, set[str]()


def resolve_account_info(
    internal_data: InternalData, config: PluginConfig, readonly=True
):
    # Initialize HTTP client
    attributes, _ = _with_defaults(config.default_attributes, internal_data.attributes)
    iuids = attributes.get(config.iuid_attribute, [])
    [cuid] = attributes.get(config.cuid_attribute, [None])
    issuer_uid = str(internal_data.auth_info.issuer)
    proxy_client = create_proxy_api_client(config)
    timeout = config.iam_api_request_timeout_seconds
    service_uid = str(internal_data.requester)
    account_info = proxy_client.lookup(
        LookupParams(
            iuids=iuids,
            service_uid=service_uid,
            issuer_uid=issuer_uid,
        ),
        timeout=timeout,
    )

    if readonly:
        return account_info

    claims = _remap(config.claims_mapping, attributes)
    # clear any claims that are no longer sent by the issuer
    if account_info.identities:
        for identity in account_info.identities:
            if identity.claims and identity.issuer_uid == issuer_uid:
                for key in identity.claims:
                    if not claims.get(key):
                        claims[key] = None

    identity = proxy_client.upsert_identity(
        UpsertIdentityParams(
            iuids=iuids,
            cuid=cuid,
            issuer_uid=issuer_uid,
            claims=claims,
        ),
        timeout=timeout,
    )

    # Inject the upserted identity into lookup.identities, matching on cuid
    # Convert to LookupIdentity with matches set to the iuids
    lookup_identity = LookupIdentity(
        cuid=identity.cuid,
        iuids=identity.iuids,
        issuer_uid=identity.issuer_uid,
        claims=identity.claims,
        created_at=identity.created_at,
        updated_at=identity.updated_at,
        matches=iuids,
    )
    account_info.identities = (
        [lookup_identity] + [i for i in account_info.identities if i.cuid != cuid]
        if account_info.identities
        else []
    )

    if account_info.accounts:
        [primary_account, *other_accounts] = account_info.accounts
        account_uid = primary_account.account_uid
        primary_account = _patch_account_profile(config, account_uid, attributes)
        # Replace the account in lookup.accounts with the updated one
        account_info.accounts = [primary_account] + other_accounts
    else:
        primary_account = _register_account(config, cuid, attributes)
        account_info.accounts = [primary_account]

    return account_info


def _patch_account_profile(
    config: PluginConfig, account_uid: str, attributes: dict[str, Any]
):
    # Update existing account profile if it differs from current attributes
    current_profile = _remap_as_model(
        AccountProfile, config.profile_mapping, attributes
    )
    account_client = create_account_api_client(config, account_uid)
    # Patch the account profile with new values
    account = account_client.patch_account_profile(
        account_uid, current_profile, timeout=5
    )
    _logger.info(f"updated account profile for {account_uid}")
    return account


def _register_account(config: PluginConfig, cuid: str, attributes: dict[str, Any]):
    # Register a new account
    accepted_policies = policies_from_attributes(attributes)
    # We can use a random UUID as the account identifier
    # Previous Perun accounts and IAM API accounts are linked by cuid through iam.identity table
    account_uid = str(uuid.uuid4())
    account_client = create_account_api_client(config, account_uid, cuid)
    profile = _remap_as_model(AccountProfile, config.profile_mapping, attributes)
    register_account_params = RegisterAccountParams(
        account_uid=account_uid,
        cuids=[cuid],
        profile=profile,
        accepted_policies=accepted_policies,
    )
    timeout = config.iam_api_request_timeout_seconds
    account = account_client.register_account(register_account_params, timeout=timeout)
    _logger.info(f"registered account {account_uid}")
    return account
