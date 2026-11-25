from logging import getLogger as get_logger

from typing import Mapping
from typing import Sequence

from requests import post as post_request
from requests import delete as delete_request

from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import SecretStr
from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper

from . import CheckerError


logger = ExtraLogger(get_logger(__name__))

API_REQUEST_TIMEOUT = 3


class Config(TableConfig):
    missing_attributes_state_key: str
    api_base_url: AnyHttpUrl
    api_key: SecretStr
    api_req_timeout: int = API_REQUEST_TIMEOUT
    enable_addition_hook: bool = True
    enable_removal_hook: bool = False


class CheckerShortlist(ResponseMicroService):
    """
    Notify the shortlist service whether the idp provided the required attributes.

    This plugin can be configured per issuer and requester.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.attribute_checker.
    name: CheckerShortlist
    description: notify the shortlist service whether the idp provided the required attributes.
    config:
      - skip: false
        requester: https://sp.example.com
        issuer: https://idp.example.com
        missing_attributes_state_key: missing_required_attributes
        api_base_url: https://api.example.com
        api_key: "a_very_secret_api_key"
        api_req_timeout: 3
        enable_addition_hook: True
        enable_removal_hook: False
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    missing_attributes_state_key=c["missing_attributes_state_key"],
                    api_base_url=c["api_base_url"],
                    api_key=c["api_key"],
                    api_req_timeout=c.get("api_req_timeout", API_REQUEST_TIMEOUT),
                    enable_addition_hook=c.get("enable_addition_hook", True),
                    enable_removal_hook=c.get("enable_removal_hook", False),
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise CheckerError("Invalid configuration") from e
        if not table_configs:
            raise CheckerError("Invalid configuration")
        hierarchial_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchial_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        missing_attributes = context.state.get(config.missing_attributes_state_key, [])
        issuer = data.auth_info.issuer
        requester = data.requester

        if missing_attributes and config.enable_removal_hook:
            self.add_idp_to_deny_list(config, issuer, requester)
        if not missing_attributes and config.enable_addition_hook:
            self.add_idp_to_allow_list(config, issuer, requester)

        return super().process(context, data)

    def add_idp_to_allow_list(self, config: Config, issuer, requester):
        request_data = {
            "json": {"entity_id": issuer},
            "timeout": config.api_req_timeout,
        }
        try:
            response = post_request(
                config.api_base_url,
                params={"access_token": config.api_key.get_secret_value()},
                **request_data,
            )
            report = {
                "message": "Add issuer to shortlist.",
                "issuer": issuer,
                "requester": requester,
                "status_code": response.status_code,
                "api_base_url": config.api_base_url,
                "request_data": request_data,
            }
            logger.debug(report)
        except Exception as exc:
            error_context = {
                "message": "Failed request to add issuer to shortlist",
                "error": exc,
            }
            logger.error(error_context)

    def add_idp_to_deny_list(self, config: Config, issuer, requester):
        request_data = {
            "json": {"entity_id": issuer},
            "timeout": config.api_req_timeout,
        }
        try:
            response = delete_request(
                config.api_base_url,
                params={"access_token": config.api_key.get_secret_value()},
                **request_data,
            )
            report = {
                "message": "Delete issuer from shortlist.",
                "issuer": issuer,
                "requester": requester,
                "status_code": response.status_code,
                "api_base_url": config.api_base_url,
                "request_data": request_data,
            }
            logger.debug(report)
        except Exception as exc:
            error_context = {
                "message": "Failed request to delete issuer from shortlist",
                "error": exc,
            }
            logger.error(error_context)
