from logging import getLogger as get_logger

from typing import Mapping
from typing import Sequence

from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper

from . import CheckerError


logger = ExtraLogger(get_logger(__name__))


class Config(TableConfig):
    missing_attributes_state_key: str
    required_attributes: list[str]


class CheckerAttributes(ResponseMicroService):
    """
    Check that the list of required (internal) attributes is present in the Response.

    The missing attributes are stored on the state
    under the key defined by the missing_attributes_state_key configuration option.

    This plugin can be configured per issuer and requester.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.attribute_checker.CheckerAttributes
    name: CheckerAttributes
    description: check that the list of required attributes is present in the Response.
    config:
      - skip: false
        requester: https://sp.example.com
        issuer: https://idp.example.com
        missing_attributes_state_key: missing_required_attributes
        required_attributes:
          - edupersontargetedid
          - displayname
          - givenname
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    missing_attributes_state_key=c["missing_attributes_state_key"],
                    required_attributes=c["required_attributes"],
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
        missing_attributes = [
            attr_name
            for attr_name in config.required_attributes
            if not data.attributes.get(attr_name)
        ]

        log_context = {
            "message": "Required attributes",
            "required_attributes": config.required_attributes,
            "missing_attributes": missing_attributes,
        }
        logger.info(log_context)

        context.state[config.missing_attributes_state_key] = missing_attributes
        return super().process(context, data)
