from logging import getLogger as get_logger

from typing import Mapping
from typing import Optional
from typing import Sequence

from satosa.micro_services.base import RequestMicroService
from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.exception import SATOSAAuthenticationError
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))


class Error(SATOSAError):
    """Generic error."""


def process_request_accrs(accrs_from_sp, accrs_order, accrs_mfa):
    sp_requires_mfa = any(accr in accrs_from_sp for accr in accrs_mfa)
    if not sp_requires_mfa:
        return accrs_from_sp

    accrs_extra = [
        accr
        for accr in accrs_order
        if accr not in accrs_from_sp
    ]
    accrs_to_request = [*accrs_from_sp, *accrs_extra]

    return accrs_to_request


def process_response_accr(accr_from_idp, accrs_from_sp, accrs_mfa):
    sp_requires_mfa = any(accr in accrs_from_sp for accr in accrs_mfa)
    idp_used_mfa = accr_from_idp in accrs_mfa
    idp_used_other_accr = accr_from_idp in accrs_from_sp
    if not sp_requires_mfa or idp_used_mfa or idp_used_other_accr:
        return accr_from_idp
    return None


class ReqConfig(TableConfig):
    accrs_mfa: list[str]
    accrs_order: list[str]
    state_key_accrs_from_sp: str


class ReqMFA(RequestMicroService):
    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[ReqConfig] = [
                ReqConfig(
                    accrs_mfa=c["accrs_mfa"],
                    accrs_order=c["accrs_order"],
                    state_key_accrs_from_sp=c["state_key_accrs_from_sp"],
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
    def process(self, context: Context, data: InternalData, config: ReqConfig):
        accrs_from_sp = (
            context.get_decoration(Context.KEY_AUTHN_CONTEXT_CLASS_REF) or []
        )
        accrs = process_request_accrs(
            accrs_from_sp, config.accrs_order, config.accrs_mfa
        )
        log_context = {
            "message": "Processed requested ACCRs from requester",
            "requester": data.requester,
            "accrs_from_sp": accrs_from_sp,
            "accrs_processed": accrs,
        }
        logger.info(log_context)
        context.state[config.state_key_accrs_from_sp] = accrs_from_sp
        context.state[Context.KEY_TARGET_AUTHN_CONTEXT_CLASS_REF] = accrs
        return super().process(context, data)


class ResConfig(TableConfig):
    accrs_mfa: list[str]
    state_key_accrs_from_sp: str
    translate_idp_accr: dict[str, str]


class ResMFA(ResponseMicroService):
    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[ResConfig] = [
                ResConfig(
                    accrs_mfa=c["accrs_mfa"],
                    state_key_accrs_from_sp=c["state_key_accrs_from_sp"],
                    translate_idp_accr=c.get("translate_idp_accr", {}),
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
    def process(self, context: Context, data: InternalData, config: ResConfig):
        accrs_from_sp = context.state.pop(config.state_key_accrs_from_sp, [])
        accr_from_idp = data.auth_info.auth_class_ref
        accr_from_idp_mapped = config.translate_idp_accr.get(accr_from_idp, accr_from_idp)

        accr = process_response_accr(accr_from_idp_mapped, accrs_from_sp, config.accrs_mfa)
        log_context = {
            "message": "Processed ACCR from issuer",
            "accrs_from_sp": accrs_from_sp,
            "accr_from_idp": accr_from_idp,
            "accr_from_idp_mapped": accr_from_idp_mapped,
            "accr_processed": accr,
        }
        logger.info(log_context)
        if accr is None:
            error_context = {
                "status_message_text": "AuthnContext not satisfied",
                "status_code_status_code_value": (
                    "urn:oasis:names:tc:SAML:2.0:protocol:NoAuthnContext"
                ),
            }
            raise SATOSAAuthenticationError(context.state, message=error_context)

        return super().process(context, data)
