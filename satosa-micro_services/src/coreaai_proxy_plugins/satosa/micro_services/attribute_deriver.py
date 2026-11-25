"""
A plugin to look through a list of internal attributes and derive values based on a strategy per requester and issuer.
It further clears all the existing internal attributes which are involved in the attribute derivation as defined as part of the strategy configurations.
"""

import logging
import re

from typing import List
from typing import Literal
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Union

from pydantic import BaseModel
from pydantic import Field

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class Error(SATOSAError):
    """Generic error."""


class BaseStrategyOptions(BaseModel):
    value_index: Optional[int] = None


class SetStrategyOptions(BaseStrategyOptions): ...


class SelectStrategyOptions(BaseStrategyOptions):
    tokenize: Optional[str] = " "
    token_index: int
    stopwords: Optional[List[str]] = []
    strip: Optional[List[str]] = []


class BaseStrategy(BaseModel):
    attr_source: str
    clear_source: bool = False
    strategy: str


class SetStrategy(BaseStrategy):
    strategy: Literal["set"]
    strategy_options: SetStrategyOptions = Field(default_factory=SetStrategyOptions)


class SelectStrategy(BaseStrategy):
    strategy: Literal["select"]
    strategy_options: SelectStrategyOptions  # Nested options for "select"


StrategyType = Union[SetStrategy, SelectStrategy]


class Config(TableConfig):
    attribute_derivation_strategies: dict[str, List[StrategyType]]
    error_url: AnyHttpUrl


class AttributeDeriver(ResponseMicroService):
    """
    example configuration:

    ```
    module: satosa.micro_services.attribute_deriver.AttributeDeriver
    name: AttributeDeriver
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

        # The URL to redirect the user in case of an error is encountered.
        error_url: https://example.tld/error

        # The strategies and rules to derive attributes.
        attribute_derivation_strategies:

        # The derived attribute name with the configuration to derive its value.
          some_attribute_foo:

        # The "set" strategy can be used to set the value of an existing internal attribute to the derived internal attribute.
        # The "set" strategy has the following options as defined using the "strategy_options" config:
        # - "value_index": (default: None (all values)) The position of the value of the existing internal attribute that will be processed. If empty all values will be processed.
        #
        # The "select" can be used to set part of a value of an existing internal attribute to the derived internal attribute.
        # The "select" strategy has the following options as defined using the "strategy_options" config:
        # - "value_index": (default: None (all values)) The position of the value of the existing internal attribute that will be processed. If empty all values will be processed.
        # - "tokenize": (default: " ") The string to use to tokenize the values before applying stopwords and stripping.
        # - "stopwords": A list of the stopwords to be removed from the values of an attribute.
        # - "strip": A list of strings that will be stripped from all the values of an attribute.
        # - "token_index": (required) The position of the tokenized value that will be used as the derived attribute value, after stopwords and stripping has been applied.
        #
        # If any strategy successfully assigns the value to the derived attribute,
        # the rest of the strategies are not evaluated and are skipped.
        #
        # If selecting an index fails the strategy is skipped.
        #
        # Each strategy can also set whether the source attribute will be cleared after successful derivation,
        # using the clear_source option. By default, the source attribute is not cleared.
        #
        # The following section contains an example configuration for attribute derivation strategies.
        # In this example configuration, the internal attributes givenmame is applied the "set" strategy
        # and the displayname is applied the "select" strategy.

            - attr_source: givenName
              clear_source: True
              strategy: set
            - attr_source: displayName
              strategy: select
              strategy_options:
                token_index: 0
                strip:
                  - ","
                stopwords:
                  - "mr\.?"
                  - "ms\.?"
                  - "mrs\.?"
                  - "dr\.?"
                  - the
                  - de
                  - la
                  - "[Ss]ir"
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            table_configs: Sequence[Config] = [
                Config(
                    attribute_derivation_strategies=c[
                        "attribute_derivation_strategies"
                    ],
                    error_url=c["error_url"],
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise Error("Invalid configuration") from e
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
        except Exception as e:
            logger.error(e)
            return Redirect(config.error_url)

        return super().process(context, data)


def _process(data: InternalData, config: Config):
    attribute_derivation_strategies = config.attribute_derivation_strategies
    for derived_attr, derivation_strategies in attribute_derivation_strategies.items():
        # get the first non-empty derived value and the strategy that derived it
        derived_attr_val, strategy = next(
            (
                (v, strategy)
                for strategy in derivation_strategies
                for v in [_process_strategy(strategy, data)]
                if v
            ),
            [None, None],
        )
        if derived_attr_val is None:
            continue

        # it should never occur that we have a value but no strategy
        assert strategy is not None

        log_report = {
            "message": "attribute derived via strategy",
            "attr_derived": derived_attr,
            "attr_derived_value": derived_attr_val,
            "attr_source": strategy.attr_source,
            "clear_source": strategy.clear_source,
            "strategy": strategy.strategy,
        }
        logger.debug(log_report)

        if strategy.clear_source:
            data.attributes.pop(strategy.attr_source, None)
        data.attributes[derived_attr] = derived_attr_val


def _process_strategy(strategy: StrategyType, data: InternalData):
    strategy_name = strategy.strategy
    if strategy_name == "set":
        _strategy_fn = _process_set_strategy
    elif strategy_name == "select":
        _strategy_fn = _process_select_strategy
    else:
        raise Error(f"Unknown strategy: {strategy_name}")

    try:
        derived_attr_val = _strategy_fn(strategy, data)
    except IndexError:
        return

    return derived_attr_val


def _process_set_strategy(strategy: SetStrategy, data: InternalData):
    attr_vals = data.attributes.get(strategy.attr_source)
    if not attr_vals:
        return None

    values = (
        [attr_vals[strategy.strategy_options.value_index]]
        if strategy.strategy_options.value_index is not None
        else attr_vals
    )
    return values


def _process_select_strategy(strategy: SelectStrategy, data: InternalData):
    attr_vals = data.attributes.get(strategy.attr_source)
    if not attr_vals:
        return None

    values = (
        [attr_vals[strategy.strategy_options.value_index]]
        if strategy.strategy_options.value_index is not None
        else attr_vals
    )
    if not values:
        return None

    rvalues = []
    for value in values:
        # XXX FIXME tokenize with regex
        for token in value.split(strategy.strategy_options.tokenize):
            # XXX FIXME do one check - combine regexes
            if any(
                re.fullmatch(sw, token)
                for sw in (strategy.strategy_options.stopwords or [])
            ):
                continue

            for s in strategy.strategy_options.strip or []:
                token = token.strip(s)
            rvalues.append(token)

    return [rvalues[strategy.strategy_options.token_index]]
