from datetime import datetime, timedelta, timezone
from logging import getLogger
from typing import Mapping, Sequence, Optional, Any, Literal
from urllib.parse import urlencode

from pydantic import HttpUrl, Field
from satosa.context import Context
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers import iamapi
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config
from coreaai_proxy_plugins.helpers.errors import error_handler
from coreaai_proxy_plugins.helpers.iamapi import (
    IamApiClient,
    current_context,
)
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper
from coreaai_proxy_plugins.helpers.sessions import SessionStoreConfig

_logger = ExtraLogger(getLogger(__name__))


class Config(TableConfig):
    mfa_verification_url: HttpUrl
    error_url: HttpUrl
    mfa_auth_class_ref: str = "https://refeds.org/profile/mfa"
    mfa_policy: Literal["always", "ttl"] = "always"
    mfa_ttl_seconds: float = Field(
        timedelta(hours=1).total_seconds(),
        ge=timedelta(seconds=30).total_seconds(),
        le=timedelta(weeks=1).total_seconds(),
    )
    mfa_verification_id_attribute: str = "mfa_verification_id"


def _redirect_on_error(
    exc: Exception,
    _plugin: ResponseMicroService,
    _ctx: Context,
    _internal_data: InternalData,
    config: Config,
):
    _logger.error(f"MFA plugin failed: {exc}", exc_info=exc)
    return Redirect(redirect_url=config.error_url)


class MFAVerification(ResponseMicroService):
    """
    Example configuration:

    ```
    module: satosa.micro_services.mfa_verification.MFAVerification
    name: MFAVerification
    config:
        mfa_verification_url: "https://test.com/"

        error_url: "https://example.com/error"

        # Whether to skip processing for this pair of requester and issuer
        # Optional; default is False
        skip: False
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)
        hierarchical_config = restructure_table_config_to_hierarchical_config(
            [Config.parse_obj(c) for c in config]
        )
        self.config = hierarchical_config
        self.session_store = SessionStoreConfig()  # type: ignore[call-arg]

    @logging_wrapper(_logger)
    @resolve_config_wrapper(_logger)
    @error_handler(_redirect_on_error)
    def process(self, context: Context, internal_data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, internal_data)
        iam_ctx = current_context()
        if iam_ctx is None:
            # iam_ctx will be None when IAM API was not triggered.
            # MFA verification will fail if the user is not registered on IAM API.
            # To avoid misconfiguration between MFA and IAM API plugins,
            # MFA verification is skipped if no IAM context is set.
            _logger.info("Skipping MFA verification because of missing IamContext")
            return super().process(context, internal_data)

        attributes = internal_data.attributes
        if config.mfa_policy == "always":
            attachment = _must_get_attr(attributes, "iam_context_id")
            max_age = None
        elif config.mfa_policy == "ttl":
            [current_identity, *_] = iam_ctx.account_info.identities or [None]
            if current_identity is None:
                raise AssertionError("has no current identity")
            attachment = current_identity.cuid
            max_age = timedelta(seconds=config.mfa_ttl_seconds)
        else:
            raise ValueError(f"Invalid MFA policy: {config.mfa_policy}")

        session_verification_id = _get_attr(
            attributes, config.mfa_verification_id_attribute
        )
        query_verification_id = (context.request or {}).get("verification_id")
        verification_id = session_verification_id or query_verification_id or None
        mfa_verification: Optional[iamapi.MFAVerification] = None
        if verification_id:
            client = iam_ctx.account_owner_api_client
            if not client:
                raise AssertionError("MFA plugin has no API client")
            try:
                # Use a minimum expiration threshold to pass the test for MFA verification validity when max_age is too short.
                # By default, this is set to 1 minute but can be configured to be longer to account for clock skew or slow network.
                mfa_verification = check_mfa_verification(
                    client,
                    verification_id=str(verification_id),
                    attachment=attachment,
                    max_age=max_age,
                )
            except MFAVerificationError as e:
                _logger.warning(f"MFA verification failed: {e}")
                _logger.info("Requiring MFA again")
                if session_verification_id:
                    # FIXME: We need to clear but None is not what the IDP initially gave...
                    internal_data.auth_info.auth_class_ref = None

                # clear the verification_id attribute from the session
                _ = internal_data.attributes.pop(
                    config.mfa_verification_id_attribute, None
                )
        if mfa_verification is None:
            resume_endpoint = iam_ctx.resume_endpoint
            redirect_url = f"{self.base_url}/{resume_endpoint}"
            query_params = {
                "attachment": attachment,
                "mfa_redirect_url": redirect_url,
            }
            if config.mfa_policy == "ttl":
                query_params["max_age_seconds"] = str(int(config.mfa_ttl_seconds))

            mfa_url = f"{config.mfa_verification_url}?{urlencode(query_params)}"

            _logger.info(f"Requiring MFA at {mfa_url}")
            self.session_store.store_session(context, internal_data)
            return Redirect(mfa_url)
        elif session_verification_id:
            _logger.info(
                f"Skipping MFA redirect. Already verified: verification_id={mfa_verification.verification_id}"
            )
        else:
            _logger.info(
                f"MFA verification succeeded: verification_id={mfa_verification.verification_id}"
            )
        internal_data.auth_info.auth_class_ref = config.mfa_auth_class_ref
        internal_data.attributes[config.mfa_verification_id_attribute] = [
            mfa_verification.verification_id
        ]
        return super().process(context, internal_data)


class MFAVerificationError(Exception):
    pass


def check_mfa_verification(
    client: IamApiClient,
    verification_id: str,
    attachment: str,
    max_age: Optional[timedelta] = None,
    timeout_seconds: float = 5,
):
    verifications = client.get_account_mfa_verifications(
        timedelta(hours=1) if max_age is None else max_age,
        verification_id=verification_id,
        timeout=timeout_seconds,
    )
    v = next(v for v in verifications if v.verification_id == verification_id)
    if v is None:
        raise MFAVerificationError("Verification not found")
    if v.attachment != attachment:
        raise MFAVerificationError(
            "Verification attachment does not match expected value"
        )
    if max_age is not None and v.verified_at + max_age < datetime.now(timezone.utc):
        raise MFAVerificationError("Verification expired")
    return v


def _get_attr(attrs: dict[str, Any], name: str) -> Optional[str]:
    value = attrs.get(name, None)
    if isinstance(value, list) and value:
        return str(value[0])
    return None


def _must_get_attr(attrs: dict[str, Any], name: str) -> str:
    value = _get_attr(attrs, name)
    if value is None:
        raise ValueError(f"Missing attribute: {name}")
    return value
