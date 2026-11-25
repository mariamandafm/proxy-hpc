from logging import getLogger as get_logger

from typing import Mapping
from typing import Sequence

from satosa.micro_services.base import RequestMicroService

from coreaai_proxy_plugins.helpers.errors import Error as _Error

from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))


class Error(_Error):
    ...


class Config(TableConfig):
    target_issuer: str


class TargetIssuer(RequestMicroService):
    """Set the target IdP (entity ID) for a request, based on the requester.

    The configuration is a list of entries resolved per requester and issuer. A
    catch-all entry (no ``requester`` and no ``issuer``) is REQUIRED as the
    fallback — requests with no more specific match use it, and without it every
    request raises a configuration error. Each entry needs a ``target_issuer``
    and may set ``skip`` to pass the request through unchanged.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.target_issuer.TargetIssuer
    name: TargetIssuer
    description: Associate a service with a specific issuer
    config:
      # required catch-all fallback (skip => pass through for unmatched requesters)
      - target_issuer: ""
        skip: true
      # send this requester to a specific IdP
      - requester: https://sp.example.com
        target_issuer: https://idp.example.com
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    target_issuer=c["target_issuer"],
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise Error("Invalid configuration") from e
        if not table_configs:
            raise Error("Invalid configuration")
        hierarchial_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchial_config


    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context, data, config):
        if not config or config.skip:
            return super().process(context, data)

        report = {
            "requester": config.requester,
            "target_issuer": config.target_issuer,
        }
        logger.info(report)

        context.decorate(context.KEY_TARGET_ENTITYID, config.target_issuer)
        return super().process(context, data)
