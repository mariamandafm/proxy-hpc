from logging import getLogger as get_logger
from typing import Mapping
from typing import Sequence

from requests import get as get_request
from requests.auth import HTTPBasicAuth

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.config import SecretStr
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))

API_REQUEST_TIMEOUT = 3

RESPONSE_STATUS_RESULTS_AUTHORIZED = [
    "ENABLED",
]

DEFAULT_AUTHZ_STRATEGY = "authorize_status"


class Config(TableConfig):
    attribute_identifier: list[str]
    authz_strategy: str
    redirect_url: AnyHttpUrl
    api_url: AnyHttpUrl
    api_user: str
    api_password: SecretStr
    api_request_timeout: int = API_REQUEST_TIMEOUT


class APIClientError(SATOSAError):
    """Generic error."""


class APIClient(ResponseMicroService):
    """Authorize the user against an external FURMS API, redirecting on failure.

    Response microservice. For each configured identifier attribute it calls the
    FURMS API (HTTP Basic auth) for the user; if the user is not authorized (or
    any error occurs) the user is redirected to ``redirect_url`` and no further
    processing happens. Two strategies are available: ``authorize_status`` (the
    default, requires an ``ENABLED`` user status) and
    ``authorize_status_and_local_user_id`` (also requires a local user id on some
    project/site).

    The configuration is a list of entries resolved per requester and issuer; a
    catch-all entry (empty/omitted ``requester`` and ``issuer``) is required as
    the fallback.

    example configuration:

    ```
    module: coreaai_proxy_plugins.satosa.micro_services.furms_authz_api.APIClient
    name: FURMSAPIClient
    config:
      - # configuration applies to any connection towards the specified requester from
        # an issuer as defined below. If the requester is empty the configuration
        # applies for any requester towards an issuer as defined below.
        # Optional; default is None
        requester: id-of-service

        # configuration applies to any connection from that issuer towards a requester
        # as defined above. If the issuer is empty the configuration applies for any
        # issuer towards a requester as defined above.
        # Optional; default is None
        issuer: id-of-provider

        # whether to skip processing for this pair of requester and issuer
        # Optional; default is False
        skip: false

        # A list of attributes that will be used to derive the user identifiers.
        # For each identifier an API call will be made to query information about the user.
        attribute_identifier:
          - "vopersonexternalid"
          - "vopersonid"

        # The authorization stragety that will be used. Available strategies
        # are "authorize_status" and "authorize_status_and_local_user_id".
        # The default strategy is "authorize_status".
        authz_strategy:

        # The URL where we will redirect the user in case of an error
        redirect_url: "https://example.org/pages/authz-error"

        # The templated URL of the API endpoint
        api_url: "https://api.example.org/v1/{user_id}"

        # The username used to authenticate at the API
        api_user: "..."

        # The passwored used to authenticate at the API
        api_password: "..."

        # Number of seconds before the HTTP request to the API times out.
        # Default is 3
        api_request_timeout: 10
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)
        table_configs: Sequence[Config] = [
            Config(
                attribute_identifier=c["attribute_identifier"],
                authz_strategy=c.get("authz_strategy", DEFAULT_AUTHZ_STRATEGY),
                redirect_url=c["redirect_url"],
                api_url=c["api_url"],
                api_user=c["api_user"],
                api_password=c["api_password"],
                api_request_timeout=c.get("api_request_timeout", API_REQUEST_TIMEOUT),
                requester=c.get("requester"),
                issuer=c.get("issuer"),
                skip=c.get("skip"),
            )
            for c in config
        ]
        hierarchial_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchial_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        try:
            _authorize(context, data, config)
        except APIClientError as e:
            logger.warning(e)
            return Redirect(config.redirect_url)
        except Exception as e:
            logger.error(e)
            return Redirect(config.redirect_url)

        return super().process(context, data)


def _authorize(context: Context, data: InternalData, config: Config):
    user_ids = [
        identifier
        for attr in config.attribute_identifier
        for identifier in (data.attributes.get(attr) or [])
    ]
    if not user_ids:
        error_context = {
            "message": "Attribute value not usable as user_id",
            "attribute_identifier": config.attribute_identifier,
            "user_ids": user_ids,
        }
        raise APIClientError(error_context)

    authorizer = (
        AUTHORIZATION_STRATEGIES.get(config.authz_strategy)
        or AUTHORIZATION_STRATEGIES[DEFAULT_AUTHZ_STRATEGY]
    )

    endpoint_urls = [
        config.api_url.format(user_id=identifier)
        for identifier in user_ids
    ]
    for endpoint_url in endpoint_urls:
        result, user_data = authorizer(endpoint_url, config)
        if result:
            return result


def _authorize_api_status(endpoint_url, config):
    try:
        response = get_request(
            endpoint_url,
            auth=HTTPBasicAuth(config.api_user, config.api_password.get_secret_value()),
            timeout=config.api_request_timeout,
        )
        logger.debug({"message": "Request response data", "data": response.text})
    except Exception as e:
        error_context = {
            "message": "Request failed with error",
            "api_url": config.api_url,
            "timeout": config.api_request_timeout,
            "error": str(e),
        }
        raise APIClientError(error_context) from e

    if response.status_code != 200:
        error_context = {
            "message": "Request returned with failure status code",
            "api_url": config.api_url,
            "status_code": response.status_code,
            "reason": response.reason,
            "text": response.text,
        }
        raise APIClientError(error_context)

    try:
        response_data = response.json()
    except Exception as e:
        error_context = {
            "message": "Response is not a JSON document",
            "api_url": config.api_url,
            "content": response.text,
            "error": str(e),
        }
        raise APIClientError(error_context) from e

    status_result = response_data.get("userStatus")
    user_is_authorized = status_result in RESPONSE_STATUS_RESULTS_AUTHORIZED
    if not user_is_authorized:
        error_context = {
            "message": "User status is not valid",
            "api_url": config.api_url,
            "status_result": status_result,
            "response_status_results_authorized": RESPONSE_STATUS_RESULTS_AUTHORIZED,
        }
        raise APIClientError(error_context)

    return user_is_authorized, response_data


def _authorize_api_status_and_local_user_id(endpoint_url, config):
    status_result, response_data = _authorize_api_status(endpoint_url, config)
    local_user_ids = [
        uid
        for site in (response_data.get("siteAccess") or [])
        for pm in (site.get("projectMemberships") or [])
        for uid in [pm.get("localUserId")]
        if uid
    ]

    user_is_authorized = status_result and local_user_ids
    if not user_is_authorized:
        error_context = {
            "message": "No local user identifier found for any project on any site",
            "api_url": config.api_url,
            "status_result": status_result,
            "response_status_results_authorized": RESPONSE_STATUS_RESULTS_AUTHORIZED,
            "local_user_ids": local_user_ids,
        }
        raise APIClientError(error_context)

    return user_is_authorized, response_data


AUTHORIZATION_STRATEGIES = {
    "authorize_status": _authorize_api_status,
    "authorize_status_and_local_user_id": _authorize_api_status_and_local_user_id,
}
