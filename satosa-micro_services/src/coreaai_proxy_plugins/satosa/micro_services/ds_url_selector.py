from logging import getLogger as get_logger

from typing import Mapping
from typing import Sequence

from satosa.backends.saml2 import SAMLBackend
from satosa.exception import SATOSAError
from satosa.micro_services.base import RequestMicroService
from satosa.context import Context
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))


class Error(SATOSAError):
    """Generic error."""


class Config(TableConfig):
    disco_url: AnyHttpUrl


class DiscoURLSelector(RequestMicroService):
    """Set the discovery service URL, based on the requester and issuer.

    The configuration is a list of entries resolved per requester and issuer. A
    catch-all entry (no ``requester`` and no ``issuer``) is REQUIRED as the
    fallback — requests with no more specific match use it, and without it every
    request raises a configuration error. Each entry needs a ``disco_url`` and
    may set ``skip`` to pass the request through unchanged.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.ds_url_selector.DiscoURLSelector
    name: DiscoURLSelector
    description: Set the discovery service URL based on the requester and issuer
    config:
      # required catch-all default discovery service
      - disco_url: https://disco-main.example.org
      # override for a specific requester/issuer pair
      - requester: https://sp-y.example.org
        issuer: https://idp-y.example.org
        disco_url: https://disco-alt.example.org
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    disco_url=c["disco_url"],
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
    def process(self, context: Context, data: InternalData, config: Config):
        """
        Set discovery URL based on issuer and requester.
        """

        if not config or config.skip:
            return super().process(context, data)

        context.decorate(SAMLBackend.KEY_SAML_DISCOVERY_SERVICE_URL, config.disco_url)
        logger.info(f"Set disco URL to {config.disco_url}")
        return super().process(context, data)
