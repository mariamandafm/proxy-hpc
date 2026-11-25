from logging import getLogger as get_logger
from urllib.parse import urlparse as parse_url
from uuid import uuid4 as gen_req_id

from typing import Mapping
from typing import Sequence

from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.config import Issuer
from coreaai_proxy_plugins.helpers.config import get_config_from_hierarchy

from coreaai_proxy_plugins.helpers.errors import Error as _Error

from coreaai_proxy_plugins.helpers.state import store as store_state
from coreaai_proxy_plugins.helpers.state import restore as restore_state
from coreaai_proxy_plugins.helpers.state import store_internal_data
from coreaai_proxy_plugins.helpers.state import restore_internal_data

from coreaai_proxy_plugins.helpers.urlsafe import serialize_payload

from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import Path
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))
DEFAULT_CONTACT_TYPES_ACCEPTED = ["support", "technical"]


class Error(_Error):
    ...


class Config(TableConfig):
    assurance_attribute: str
    assurance_attribute_values_iap_accepted: list[str]
    assurance_attribute_values_id_accepted: list[str]
    user_name_attribute: str
    contact_types_accepted: list[str] = DEFAULT_CONTACT_TYPES_ACCEPTED
    redirect_url: AnyHttpUrl
    response_endpoint_base_path: Path
    state_key_req_id: str


class CheckerAssurance(ResponseMicroService):
    """
    Check that the user has sufficient assurance level.

    This plugin can be configured per issuer and requester.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.attribute_checker.assurance.CheckerAssurance
    name: CheckerAssurance
    config:
      - skip: false
        requester: https://sp.example.com
        issuer: https://idp.example.com
        assurance_attribute: epa
        assurance_attribute_values_iap_accepted:
          - https://refeds.org/assurance/IAP/medium
          - https://refeds.org/assurance/IAP/high
        assurance_attribute_values_id_accepted:
          - https://refeds.org/assurance/ID/UNIQUE
          - https://refeds.org/assurance/ID/eppn-unique-no-reassign
        user_name_attribute: display_name
        contact_types_accepted:
          - "support"
          - "technical"
        redirect_url: https://example.com/approve-aup
        response_endpoint_base_path: /ack-assurance
        state_key_req_id: casri
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    assurance_attribute=c["assurance_attribute"],
                    assurance_attribute_values_iap_accepted=c["assurance_attribute_values_iap_accepted"],
                    assurance_attribute_values_id_accepted=c["assurance_attribute_values_id_accepted"],
                    user_name_attribute=c["user_name_attribute"],
                    contact_types_accepted=c.get("contact_types_accepted", DEFAULT_CONTACT_TYPES_ACCEPTED),
                    redirect_url=c["redirect_url"],
                    response_endpoint_base_path=c["response_endpoint_base_path"],
                    state_key_req_id=c["state_key_req_id"],
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

    def register_endpoints(self):
        """
        Register aas module endpoints
        :rtype: list[(srt, (satosa.context.Context) -> Any)]
        :return: A list of endpoints bound to a function
        """
        keys_requester_first = next(iter(self.config.keys()))
        keys_issuer_first = next(iter(self.config[keys_requester_first].keys()))
        config_def = self.config[keys_requester_first][keys_issuer_first]

        url_map = [(f"^{config_def.response_endpoint_base_path}/.*$", self._handle_response)]
        return url_map

    def _handle_response(self, context):
        logger.bind("session_id", context.state.session_id)
        logger.info("Continue processing")

        data = restore_internal_data(context.state)
        if not data:
            err_ctx = {"message": "Invalid request data."}
            raise Error(err_ctx)

        requester = data.requester
        issuer = data.auth_info.issuer or Issuer("")
        config = get_config_from_hierarchy(self.config, requester, issuer)
        req_id = restore_state(context.state, config.state_key_req_id)
        (*_, req_id_param) = context._path.split("/")
        if not req_id or not req_id_param or req_id != req_id_param:
            err_ctx = {
                "message": "Invalid request id.",
                "req_id": req_id,
                "req_id_param": req_id_param,
                "requester": requester,
                "issuer": issuer,
            }
            raise Error(err_ctx)

        return super().process(context, data)

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        assurances = data.attributes.get(config.assurance_attribute) or []
        satisfied_iap = any(
            assurance in config.assurance_attribute_values_iap_accepted
            for assurance in assurances
        )
        satsfied_id = any(
            assurance in config.assurance_attribute_values_id_accepted
            for assurance in assurances
        )
        if satisfied_iap and satsfied_id:
            return super().process(context, data)

        req_id = gen_req_id().hex
        return_url = f"{self.base_url}/{config.response_endpoint_base_path}/{req_id}"
        issuer_md = data.metadata.get(data.auth_info.issuer, {})

        idp_contact_emails = (
            email.replace("mailto:", "", 1)
            for contact_type in config.contact_types_accepted
            for contact in (issuer_md.get("contacts") or [])
            if contact.get("contact_type") == contact_type
            for email in (contact.get("email_address") or [])
            if email.startswith("mailto:")
        )
        idp_contact_email = next(idp_contact_emails, None)
        idp_display_name = issuer_md.get("display_name")

        user_names = data.attributes.get(config.user_name_attribute) or []
        user_display_name = next(iter(user_names), None)

        tmp_redirect_url_obj = parse_url(config.redirect_url)
        payload = serialize_payload(
            {
                "idp_contact_email": idp_contact_email,
                "idp_display_name": idp_display_name,
                "user_display_name": user_display_name,
                "return_url": return_url,
            }
        )
        newpath = f"{tmp_redirect_url_obj.path}/{payload}"
        redirect_url_obj = tmp_redirect_url_obj._replace(path=newpath)
        redirect_url = redirect_url_obj.geturl()

        log_context = {
            "message": "Redirecting user because assurance level was not sufficient",
            "assurance_attribute": config.assurance_attribute,
            "assurances": assurances,
            "assurance_attribute_values_iap_accepted": config.assurance_attribute_values_iap_accepted,
            "assurance_attribute_values_id_accepted": config.assurance_attribute_values_id_accepted,
            "state_key_req_id": config.state_key_req_id,
            "return_url": return_url,
            "redirect_url": redirect_url,
        }
        logger.info(log_context)

        store_internal_data(context.state, data.to_dict())
        store_state(context.state, config.state_key_req_id, req_id)
        logger.debug({"state_before_redirect": context.state})
        return Redirect(redirect_url)
