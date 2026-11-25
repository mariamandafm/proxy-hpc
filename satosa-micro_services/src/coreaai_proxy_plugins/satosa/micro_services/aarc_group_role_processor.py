"""
SATOSA microservice that encodes group and role information
using the AARC guidelines
"""
from logging import getLogger as get_logger

from urllib.parse import quote

from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.config import parse_config
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))


class AarcGroupRoleProcessor(ResponseMicroService):
    """
    Encodes group and role information following the AARC G069 guidelines.

    References:
      - https://aarc-community.org/guidelines/aarc-g069/
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    @logging_wrapper(logger)
    def process(self, context, internal_data):
        requester = internal_data.requester
        issuer = internal_data.auth_info.issuer
        parsed_config = parse_config(self.config, issuer, requester)
        config = (
            parsed_config["by-iss-req"] if isinstance(
                parsed_config["by-iss-req"],
                dict
            ) else parsed_config["by-req-iss"] if isinstance(
                parsed_config["by-req-iss"],
                dict
            ) else parsed_config["by-requester"] if isinstance(
                parsed_config["by-requester"],
                dict
            ) else parsed_config["by-issuer"] if isinstance(
                parsed_config["by-issuer"],
                dict
            ) else {}
        )

        logger.debug(f"Initialized with configuration: {config}")

        if (config == {} or config.get('disabled')):
            return super().process(context, internal_data)

        urn_ns = config["urn_namespace"]
        auth = config.get("attribute_authority")
        attr_groups_from = config["from_group_role_attribute"]
        attr_groups_to = config["to_group_role_attribute"]
        groups: list = internal_data.attributes.get(attr_groups_from) or []
        groups_to: list = internal_data.attributes.get(attr_groups_to) or []
        clear_groups_from = config.get("clear_from_group_role_attribute", True)

        groups_aarc = [
            (
                f"{urn_ns}:group:{group_quoted}#{auth}"
                if auth
                else f"{urn_ns}:group:{group_quoted}"
            )
            for group in groups
            for group_quoted in [quote(group, safe="/:")]
        ]

        logger.debug(
            {
                "message": "Generated groups with the AARC G069 format",
                "groups": groups,
                "groups_aarc": groups_aarc,
                "groups_to": groups_to,
            }
        )

        if groups_aarc:
            internal_data.attributes[attr_groups_to] = groups_to + groups_aarc

        if clear_groups_from:
            _ = internal_data.attributes.pop(attr_groups_from, None)

        return super().process(context, internal_data)
