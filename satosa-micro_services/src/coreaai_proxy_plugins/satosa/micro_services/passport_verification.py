from collections.abc import Mapping, Sequence
from logging import getLogger
from urllib.parse import urlencode

from pydantic import HttpUrl, Field
from satosa.context import Context
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.config import (
    restructure_table_config_to_hierarchical_config,
    TableConfig,
    resolve_config_wrapper,
)
from coreaai_proxy_plugins.helpers.errors import error_handler
from .coreaai_proxy_pluginshelpers.iamapi import current_context, Identity
from coreaai_proxy_plugins.helpers.logging import ExtraLogger, logging_wrapper
from coreaai_proxy_plugins.helpers.sessions import SessionStoreConfig

_logger = ExtraLogger(getLogger(__name__))


def default_icao_mapping():
    """
    'primary_identifier', d.primary_identifier,
    'secondary_identifier', d.secondary_identifier,
    'date_of_birth', d.date_of_birth,
    'year_of_birth', d.year_of_birth,
    'nationality', d.nationality,
    'issuing_country', d.issuing_country,
    'gender', d.gender) as claims
    """
    return dict(
        surname="primary_identifier",
        givenname="secondary_identifier",
        dateofbirth="date_of_birth",
        citizenship="nationality",
        sex="gender",
    )


class PassportVerificationConfig(TableConfig):
    error_url: HttpUrl
    providers: list[str] = Field(default_factory=list)
    verification_url: HttpUrl
    icao_mapping: dict[str, str] = Field(default_factory=default_icao_mapping)

    def is_passport_identity(self, identity: Identity) -> bool:
        # Lookup is already returning not expired passports enrolled this year
        return identity.issuer_uid in self.providers


def _redirect_on_error(
    exc: Exception,
    _plugin: ResponseMicroService,
    _ctx: Context,
    _internal_data: InternalData,
    config: PassportVerificationConfig,
):
    _logger.error(f"Passport verification plugin failed: {exc}")
    return Redirect(redirect_url=config.error_url)


class PassportVerification(ResponseMicroService):
    """
    Example configuration:

    ```
    module: satosa.micro_services.passport_verification.PassportVerification
    name: PassportVerification
    config:
        verification_url: "https://test.example/"
        providers: ["https://saas.readid.example/geant/myaccessid/coreaai"]
        error_url: "https://test.example/error"

        # Whether to skip processing for this pair of requester and issuer
        # Optional; default is False
        skip: False
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)
        hierarchical_config = restructure_table_config_to_hierarchical_config(
            [PassportVerificationConfig.parse_obj(c) for c in config]
        )
        self.config = hierarchical_config
        self.session_store = SessionStoreConfig()

    @logging_wrapper(_logger)
    @resolve_config_wrapper(_logger)
    @error_handler(_redirect_on_error)
    def process(
        self,
        context: Context,
        internal_data: InternalData,
        config: PassportVerificationConfig,
    ):
        if not config or config.skip:
            return super().process(context, internal_data)

        iam_ctx = current_context()
        if iam_ctx is None:
            # iam_ctx will be None when IAM API was not triggered.
            # Passport verification will fail if user is not registered on IAM API.
            # To avoid misconfiguration between Passport and IAM API plugins,
            # Passport verification is skipped if no IAM context is set.
            _logger.info("Skipping Passport verification because of missing IamContext")
            return super().process(context, internal_data)

        account_info = iam_ctx.account_info

        identities = [
            i for i in account_info.identities if config.is_passport_identity(i)
        ]
        if not identities:
            resume_endpoint = iam_ctx.resume_endpoint
            redirect_url = f"{self.base_url}/{resume_endpoint}"
            query_params = urlencode({"redirect_url": redirect_url})
            passport_verification_url = f"{config.verification_url}?{query_params}"
            self.session_store.store_session(context, internal_data)
            return Redirect(redirect_url=passport_verification_url)

        _logger.info("Account has enrolled passports")
        icao_claims = identities[0].claims
        internal_data.attributes |= {
            to_key: [icao_claims.get(from_key)]
            for to_key, from_key in config.icao_mapping.items()
        }
        return super().process(context, internal_data)
