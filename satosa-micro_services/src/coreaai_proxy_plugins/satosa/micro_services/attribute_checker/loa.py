from logging import getLogger as get_logger
from urllib.parse import urlparse as parse_url

from typing import Mapping
from typing import Sequence

from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.errors import Error as _Error

from coreaai_proxy_plugins.helpers.urlsafe import serialize_payload

from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))


class Error(_Error):
    ...


class Config(TableConfig):
    attribute_loa: str
    required_values: list[str]
    redirect_url: AnyHttpUrl


class CheckerLoA(ResponseMicroService):
    """
    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.attribute_checker.CheckerLoA
    name: CheckerLoA
    description: Check if the required LoA is matched
    config:
      - skip: false
        requester: https://sp.example.com
        issuer: https://idp.example.com
        attribute_loa: __accr__
        required_values:
          - http://eidas.europa.eu/NotNotified/LoA/substantial
          - http://eidas.europa.eu/NotNotified/LoA/high
        redirect_url: https://example.org/loa-error
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    attribute_loa=c["attribute_loa"],
                    required_values=c["required_values"],
                    redirect_url=c["redirect_url"],
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

        loa_values = (
            [data.auth_info.auth_class_ref]
            if config.attribute_loa == "__accr__"
            else data.attributes.get(config.attribute_loa)
        )
        loa_satisfied = any(value in config.required_values for value in loa_values)

        report = {
            "required_values": config.required_values,
            "user_loa_values": loa_values,
            "loa_satisfied": loa_satisfied,
        }
        logger.info(report)

        if not loa_satisfied:
            issuer_md = data.metadata.get(data.auth_info.issuer, {})
            idp_display_name = issuer_md.get("display_name")

            tmp_redirect_url_obj = parse_url(config.redirect_url)
            payload = serialize_payload(
                {
                    "idp_display_name": idp_display_name,
                    "required_values": config.required_values,
                    "user_loa_values": loa_values,
                }
            )
            newpath = f"{tmp_redirect_url_obj.path}/{payload}"
            redirect_url_obj = tmp_redirect_url_obj._replace(path=newpath)
            redirect_url = redirect_url_obj.geturl()

            return Redirect(redirect_url)

        return super().process(context, data)
