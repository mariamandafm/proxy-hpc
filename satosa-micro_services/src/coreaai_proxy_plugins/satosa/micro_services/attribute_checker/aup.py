from logging import getLogger as get_logger
from urllib.parse import urlparse as _parse_url
from urllib.parse import parse_qsl as _parse_qsl
from urllib.parse import urlencode as _encode_qp

from typing import Mapping
from typing import Sequence

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

from . import CheckerError


logger = ExtraLogger(get_logger(__name__))


class Config(TableConfig):
    aup_attribute: str
    aup_value: str
    redirect_url: AnyHttpUrl
    continue_url_state_key: str


class CheckerAUP(ResponseMicroService):
    """
    Check that the user has accepted the given AUP, else redirect them to do so.

    This plugin can be configured per issuer and requester.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.attribute_checker.CheckerAUP
    name: CheckerAUP
    description: enforce users have accepted the latest AUP
    config:
      - skip: false
        requester: https://sp.example.com
        issuer: https://idp.example.com
        aup_attribute: aup
        aup_value: aup_2022_04_03
        redirect_url: https://example.com/approve-aup
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    aup_attribute=c["aup_attribute"],
                    aup_value=c["aup_value"],
                    redirect_url=c["redirect_url"],
                    continue_url_state_key=c["continue_url_state_key"],
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
        if not config or config.skip:
            return super().process(context, data)

        aup_accepted_by_user = data.attributes.get(config.aup_attribute) or []
        if config.aup_value in aup_accepted_by_user:
            return super().process(context, data)

        continue_url = context.state.get(config.continue_url_state_key) or ""
        redirect_url_obj = _parse_url(config.redirect_url)
        query_params = {
            **dict(_parse_qsl(redirect_url_obj.query)),
            "targetnew": continue_url,
        }
        qs_new = _encode_qp(query_params)
        redirect_url_obj_new = redirect_url_obj._replace(query=qs_new)
        redirect_url = redirect_url_obj_new.geturl()

        log_context = {
            "message": "Redirecting user because they have not accepted the AUP",
            "aup_accepted_by_user": aup_accepted_by_user,
            "aup_value": config.aup_value,
            "redirect_url": config.redirect_url,
        }
        logger.info(log_context)

        return Redirect(redirect_url)
