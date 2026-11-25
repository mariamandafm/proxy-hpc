from base64 import urlsafe_b64encode
from json import dumps as serialize_as_json
from logging import getLogger as get_logger

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
    missing_attributes_state_key: str
    redirect_url: AnyHttpUrl


class CheckerRedirect(ResponseMicroService):
    """
    Redirect the user to the specified URL if the required attributes are missing.

    This plugin can be configured per issuer and requester.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.attribute_checker.CheckerRedirect
    name: CheckerRedirect
    description: redirect the user to the specified URL if the required attributes are missing.
    config:
      - skip: false
        requester: https://sp.example.com
        issuer: https://idp.example.com
        missing_attributes_state_key: missing_required_attributes
        redirect_url: https://example.com/missing-attributes
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    missing_attributes_state_key=c["missing_attributes_state_key"],
                    redirect_url=c["redirect_url"],
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

        missing_attributes = context.state.get(config.missing_attributes_state_key, [])
        if not missing_attributes:
            return super().process(context, data)

        mdstore = data.get("metadata", {})
        requester = data.requester
        requester_name = mdstore.get(requester, {}).get("display_name") or requester
        issuer = data.auth_info.issuer
        issuer_name = mdstore.get(issuer, {}).get("display_name") or issuer
        contacts = mdstore.get(issuer, {}).get("contacts", [])

        model = {
            "requester": requester,
            "requester_name": requester_name,
            "issuer": issuer,
            "issuer_name": issuer_name,
            "contacts": contacts,
            "missing_attributes": missing_attributes,
        }

        payload = serialize_as_json(model)
        payload_enc = payload.encode("utf-8")
        payload_b64 = urlsafe_b64encode(payload_enc)
        payload_b64_dec = payload_b64.decode("utf-8")
        redirect_url = "{location}/{data}".format(
            location=config.redirect_url, data=payload_b64_dec
        )

        return Redirect(redirect_url)
