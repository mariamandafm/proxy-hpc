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


class UserTypeCheckerError(SATOSAError):
    pass


class Config(TableConfig):
    registration_status_attr: str
    registered_value: str
    redirect_url: AnyHttpUrl


class UserTypeChecker(ResponseMicroService):
    """
    Plugin that checks if the user is registered based on a configurable field.
    If the user is not registered, redirects to a registration page.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.user_type_checker.UserTypeChecker
    name: UserTypeChecker
    config:
    -   registration_status_attr: "{{ entry.authn_id_attr }}" # what attribute to check
        registered_value: "{{ entry.authn_id_attr }}" # what value is considered registered
        redirect_url: "{{ entry.authn_id_attr }}" # what URL to redirect if user not registered
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
                    registration_status_attr=c["registration_status_attr"],
                    registered_value=c["registered_value"],
                    redirect_url=c["redirect_url"],
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise UserTypeCheckerError("Invalid configuration") from e

        if not table_configs:
            raise UserTypeCheckerError("Invalid configuration")

        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )

        self.config = hierarchical_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        user_type = next(
            iter(data.attributes.get(config.registration_status_attr) or [None])
        )
        is_user_type_registered = user_type == config.registered_value

        log_report = {
            "message": "User registration type status",
            "user_type": user_type,
            "is_user_type_registered": is_user_type_registered,
            "user_type_attr": config.registration_status_attr,
            "user_type_registered_value": config.registered_value,
        }
        logger.info(log_report)

        if not is_user_type_registered:
            return Redirect(config.redirect_url)

        return super().process(context, data)
