from logging import getLogger as get_logger
from typing import Mapping
from typing import Sequence

from requests import post as post_request
from requests.auth import HTTPBasicAuth

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import SecretStr
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))

API_REQUEST_TIMEOUT = 3


class Config(TableConfig):
    user_id_attribute: str
    api_url: AnyHttpUrl
    api_user: str
    api_password: SecretStr
    api_request_timeout: int = API_REQUEST_TIMEOUT


class ElixirStatsUploaderError(SATOSAError):
    """Generic error."""


class ElixirStatsUploader(ResponseMicroService):
    """
    example configuration:

    ```
    module: satosa.micro_services.elixir_stats_uploader.ElixirStatsUploader
    name: ElixirStatsUploader
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

        # The internal attribute of SATOSA from where we get the CUID of the user
        user_id_attribute: subject-id

        # The URL of the Elixir Stats Service API
        api_url:

        # The username used to authenticate at the Elixir Stats Service API
        api_user:

        # The passwored used to authenticate at the Elixir Stats Service API
        api_password:

        # Number of seconds before the HTTP request to the SBS API times out.
        # Default is 3
        api_request_timeout:
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)
        table_configs: Sequence[Config] = [
            Config(
                user_id_attribute=c["user_id_attribute"],
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
        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchical_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        try:
            _process(data, config)
            logger.info("Authentication information posted to Elixir stats service successfully")
        except Exception as e:
            logger.warning(e)

        return super().process(context, data)


def _process(data: InternalData, config: Config):
    requester = data.requester
    issuer = data.auth_info.issuer
    user_id = next(iter(data.attributes.get(config.user_id_attribute) or []), None)

    if not user_id:
        error_context = {
            "message": "Attribute value not usable as user_id",
            "user_id_attribute": config.user_id_attribute,
            "user_id": user_id,
        }
        raise ElixirStatsUploaderError(error_context)

    request_payload = {
        "userId": user_id,
        "serviceIdentifier": requester,
        "serviceName": data.metadata.get(requester, {}).get("display_name", None),
        "idpIdentifier": issuer,
        "idpName": data.metadata.get(issuer, {}).get("display_name", None),
    }

    try:
        response = post_request(
            config.api_url,
            auth=HTTPBasicAuth(config.api_user, config.api_password.get_secret_value()),
            json=request_payload,
            timeout=config.api_request_timeout,
        )
    except Exception as e:
        error_context = {
            "message": "Request failed with error",
            "api_url": config.api_url,
            "request_data": request_payload,
            "timeout": config.api_request_timeout,
        }
        raise ElixirStatsUploaderError(error_context) from e

    if response.status_code != 200:
        error_context = {
            "message": "Request returned with failure status code",
            "api_url": config.api_url,
            "request_data": request_payload,
            "status_code": response.status_code,
            "reason": response.reason,
            "response_payload": response.content,
        }
        raise ElixirStatsUploaderError(error_context)
