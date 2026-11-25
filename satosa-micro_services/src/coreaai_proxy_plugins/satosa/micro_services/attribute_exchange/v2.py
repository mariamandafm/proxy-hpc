"""
Copy the values of one attribute to another attribute in a configuratble way.
"""

import logging
from enum import Enum
from enum import unique
from typing import Any
from typing import MutableMapping

from pydantic import BaseModel
from pydantic import ConfigDict

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


@unique
class CopyStrategy(str, Enum):
    MERGE = "merge"
    OVERWRITE = "overwrite"


class CopyRule(BaseModel):
    target_attribute: str
    source_attributes: list[str]
    strategy: CopyStrategy
    clear_source: bool

    class Config:
        use_enum_values = True


class Error(SATOSAError):
    pass


class Config(TableConfig):
    copy_rules: list[CopyRule]


class AttributeExchange(ResponseMicroService):
    """
    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.attribute_exchange.AttributeExchange
    name: Copy the value of one attribute to another attribute.
    config:
      - # the rules that define which values need to be copied and how
        copy_rules:
        - # the target attribute to put the values from the source attributes.
          target_attribute: ...

          # the attributes whose values will be copied to the target attributes.
          source_attributes: [...]

          # the strategy to use to copy the values to the target attributes.
          # Valid values: overwrite, merge
          # Default: overwrite
          strategy: overwrite

          # Whether the source attribute should be cleared.
          # Default: false
          clear_source: true

        requester:
        issuer:
        skip:
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = restructure_table_config_to_hierarchical_config(
            [Config.parse_obj(c) for c in config]
        )

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        for rule in config.copy_rules:
            result = process_rule(rule, data.attributes)

            log_report = {
                "messsage": "Copied values",
                "rule": rule.dict(),
                "target_values": result[0][1],
                "source_values": result[1],
            }
            logger.info(log_report)

        return super().process(context, data)


def process_rule(rule: CopyRule, attributes: MutableMapping[str, Any]):
    values_existing = attributes.get(rule.target_attribute) or []
    values_new = [v for attr in rule.source_attributes for v in attributes.get(attr, [])]

    if not values_new:
        if values_existing:
            attributes[rule.target_attribute] = [*values_existing]
    elif rule.strategy == CopyStrategy.OVERWRITE.value:
        attributes[rule.target_attribute] = [*values_new]
    elif rule.strategy == CopyStrategy.MERGE.value:
        attributes[rule.target_attribute] = [*values_existing, *values_new]

    if rule.clear_source:
        for attr in rule.source_attributes:
            if attr != rule.target_attribute:
                attributes.pop(attr, None)

    return (
        (rule.target_attribute, attributes.get(rule.target_attribute)),
        (
            (attr, values)
            for attr in rule.source_attributes
            for values in attributes.get(attr)
        ),
    )
