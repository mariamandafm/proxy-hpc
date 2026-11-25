import logging
from typing import Sequence

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.config import (
    TableConfig,
    restructure_table_config_to_hierarchical_config,
    resolve_config_wrapper,
)
from coreaai_proxy_plugins.helpers.logging import ExtraLogger, logging_wrapper

logger = ExtraLogger(logging.getLogger(__name__))


class AuthnIdDeriverError(SATOSAError):
    pass


class Config(TableConfig):
    authn_id_attr: str


class AuthnIdDeriver(ResponseMicroService):
    """
    Exposes Authentication Authority as an attribute

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.authn_id_deriver.AuthnIdDeriver
    name: AuthnIdDeriver
    config:
    -   authn_id_attr: "{{ entry.authn_id_attr }}" # what attribute name to expose
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
                    authn_id_attr=c["authn_id_attr"],
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise AuthnIdDeriverError("Invalid configuration") from e

        if not table_configs:
            raise AuthnIdDeriverError("Invalid configuration")

        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )

        self.config = hierarchical_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context, internal_data, config: Config):
        if not config or config.skip:
            return super().process(context, internal_data)

        authority = internal_data.auth_info.authority
        if authority:
            internal_data.attributes[config.authn_id_attr] = [authority]

        log_report = {
            "message": "Authn authority deriver",
            "authority": authority,
            "authn_id_attr": config.authn_id_attr,
        }
        logger.info(log_report)

        return super().process(context, internal_data)
