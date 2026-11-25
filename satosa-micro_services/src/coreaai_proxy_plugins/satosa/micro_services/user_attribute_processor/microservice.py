import logging
from typing import Sequence, Optional

from pydantic import BaseModel
from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.config import (
    TableConfig,
    restructure_table_config_to_hierarchical_config,
    resolve_config_wrapper,
)
from coreaai_proxy_plugins.helpers.logging import logging_wrapper, ExtraLogger
from .actions import Action
from .predicates import Predicate

logger = ExtraLogger(logging.getLogger(__name__))


class UserAttributeProcessorError(SATOSAError):
    pass


class Rule(BaseModel):
    name: Optional[str]
    predicate: Predicate
    success_actions: list[Action] = []
    failure_actions: list[Action] = []


class Config(TableConfig):
    rules: list[Rule]


class UserAttributeProcessor(ResponseMicroService):

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    rules=c["rules"],
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise UserAttributeProcessorError("Invalid configuration") from e

        if not table_configs:
            raise UserAttributeProcessorError("Invalid configuration")

        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )

        self.config = hierarchical_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        for rule in config.rules:
            logger.info(f"Processing {rule.name}")

            result = rule.predicate.check(data)

            actions = rule.success_actions if result else rule.failure_actions

            for action in actions:
                if action.is_terminal:
                    terminal_result = action.process(data)

                    # Returning a false value here means continue to next microservice
                    if not terminal_result:
                        return super().process(context, data)

                    # Else, the processor wants to do something else i.e. redirect
                    return terminal_result

                action.process(data)

            return super().process(context, data)
