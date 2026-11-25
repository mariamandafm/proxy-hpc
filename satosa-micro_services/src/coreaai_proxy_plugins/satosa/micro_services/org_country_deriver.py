import logging
from typing import Sequence
from typing import Optional

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.config import (
    TableConfig,
    restructure_table_config_to_hierarchical_config,
    resolve_config_wrapper,
)
from coreaai_proxy_plugins.helpers.logging import ExtraLogger, logging_wrapper

logger = ExtraLogger(logging.getLogger(__name__))


class OrgCountryDeriverError(SATOSAError):
    pass


class Config(TableConfig):
    org_country_attr: str
    reg_auth_to_country: dict[str, str]
    default_value: Optional[str]


class OrgCountryDeriver(ResponseMicroService):
    """
    Exposes Federation/Organization Country as an attribute

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.org_country_deriver.OrgCountryDeriver
    name: OrgCountryDeriver
    config:
      - org_country_attr: org_country_attr  # The internal attribute to set the country of registration
        reg_auth_to_country:                # Map registration_authority to country code
          "http://www.surfconext.nl/": "NL
          "http://www.swamid.se/": "SE"
        default_value: null                 # The value to set if none is derived
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
                    org_country_attr=c["org_country_attr"],
                    reg_auth_to_country=c["reg_auth_to_country"],
                    default_value=c.get("default_value"),
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise OrgCountryDeriverError("Invalid configuration") from e

        if not table_configs:
            raise OrgCountryDeriverError("Invalid configuration")

        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )

        self.config = hierarchical_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context, internal_data, config: Config):
        if not config or config.skip:
            return super().process(context, internal_data)

        idp_data = internal_data.metadata.get(internal_data.auth_info.issuer, {})
        registration_authority = idp_data.get("registration_info", {}).get(
            "registration_authority"
        )
        org_country = (
            config.reg_auth_to_country.get(registration_authority, config.default_value)
            if registration_authority
            else config.default_value
        )

        log_ctx = {
            "message": "Country of organization resolved based on registration authority",
            "org_country": org_country,
            "registration_authority": registration_authority,
        }
        logger.info(log_ctx)

        if org_country:
            internal_data.attributes[config.org_country_attr] = [org_country]

        return super().process(context, internal_data)
