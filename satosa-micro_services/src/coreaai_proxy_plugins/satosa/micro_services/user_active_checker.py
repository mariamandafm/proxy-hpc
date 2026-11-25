import logging
from typing import Sequence

from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import (
    AnyHttpUrl,
    TableConfig,
    restructure_table_config_to_hierarchical_config,
    resolve_config_wrapper,
)
from coreaai_proxy_plugins.helpers.logging import ExtraLogger, logging_wrapper

logger = ExtraLogger(logging.getLogger(__name__))


def _find_matching_country_code(mapping, registration_authority):
    return mapping.get(registration_authority, None)


class UserActiveCheckerError(SATOSAError):
    pass


class Config(TableConfig):
    user_status_attr: str
    active_value: str
    redirect_url: AnyHttpUrl


class UserActiveChecker(ResponseMicroService):
    """
    Checks the value of a specified attribute to check if the user is active

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.user_active_checker.UserActiveChecker
    name: UserActiveChecker
    config:
    -   user_status_attr: "{{ entry.user_status_attr }}" # what attribute to check
        active_value: "{{ entry.active_value }}" # what value is considered active
        redirect_url: "{{ entry.redirect_url }}" # what URL to redirect if inactive
        requester: "{{ entry.requester }}"
        issuer: "{{ entry.issuer }}"
        skip: {{ entry.skip }}
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    user_status_attr=c["user_status_attr"],
                    active_value=c["active_value"],
                    redirect_url=c["redirect_url"],
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise UserActiveCheckerError("Invalid configuration") from e

        if not table_configs:
            raise UserActiveCheckerError("Invalid configuration")

        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )

        self.config = hierarchical_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        user_status = next(iter(data.attributes.get(config.user_status_attr) or [None]))
        is_user_status_active = user_status == config.active_value

        log_report = {
            "message": "User activation status",
            "user_status": user_status,
            "is_user_status_active": is_user_status_active,
            "user_status_attr": config.user_status_attr,
            "user_status_active_value": config.active_value,
        }
        logger.info(log_report)

        if not is_user_status_active:
            return Redirect(config.redirect_url)

        return super().process(context, data)
