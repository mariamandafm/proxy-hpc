import logging
from copy import deepcopy
from typing import Iterable

from satosa.micro_services.base import ResponseMicroService
from satosa.exception import SATOSAError

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class DedupError(SATOSAError):
    """Generic error for this module"""


class AttributeDeduper(ResponseMicroService):
    """
    Deduplicate attribute values.

    example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.dedup.AttributeDeduper
    name: deduplicate attribute values
    config:
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @logging_wrapper(logger)
    def process(self, context, data):
        issuer = data.auth_info.issuer
        requester = data.requester
        attributes = deepcopy(data.attributes)

        dedup_attributes = {
            name: list(dedup_values)
            for name, values in attributes.items()
            if (
                isinstance(values, Iterable)
                and not isinstance(values, str)
                and len(values) > 1
            )
            for dedup_values in [set(values)]
            if len(values) != len(dedup_values)
        }

        report = {
            "issuer": issuer,
            "requester": requester,
            "dedup_attributes": dedup_attributes.keys(),
        }
        report_dbg = {
            **report,
            "dedup_attributes": dedup_attributes,
        }
        logger.debug(report_dbg)
        logger.info(report)

        new_attributes = {**attributes, **dedup_attributes}
        data.attributes = new_attributes
        return super().process(context, data)
