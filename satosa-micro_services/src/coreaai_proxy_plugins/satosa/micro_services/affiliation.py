from logging import getLogger as get_logger

from typing import Mapping
from typing import Optional
from typing import Sequence

from toolz.itertoolz import unique as uniquify_seq

from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))


class Error(SATOSAError):
    """Generic error."""


class Config(TableConfig):
    vpea_attribute: str
    epsa_attribute: str
    epa_attribute: str
    sho_attribute: str
    eppn_attribute: str
    scope_fallback: Optional[str] = None


class AffiliationDeriver(ResponseMicroService):
    """
    AARC-G057: Inferring and constructing origin-affiliation information across infrastructures.

    This plugin can be configured per issuer and requester.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.affiliation.AffiliationDeriver
    name: aarc_g057
    description: inferring and constructing origin-affiliation information across infrastructures.
    config:
      - skip: false
        requester: https://sp.example.com
        issuer: https://idp.example.com
        vpea_attribute: vpea
        epsa_attribute: epsa
        epa_attribute: edupersonaffiliation
        sho_attribute: schachomeorganization
        eppn_attribute: eppn
        scope_fallback: optionally-fallback-to-this-scope-probably-for-a-specifc-idp
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    vpea_attribute=c["vpea_attribute"],
                    epsa_attribute=c["epsa_attribute"],
                    epa_attribute=c["epa_attribute"],
                    sho_attribute=c["sho_attribute"],
                    eppn_attribute=c["eppn_attribute"],
                    scope_fallback=c.get("scope_fallback"),
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
        issuer = data.auth_info.issuer
        requester = data.requester

        epsa = data.attributes.get(config.epsa_attribute) or []
        vpea = data.attributes.get(config.vpea_attribute) or []
        eppn = data.attributes.get(config.eppn_attribute) or []
        epa = data.attributes.get(config.epa_attribute) or []
        sho = data.attributes.get(config.sho_attribute) or []

        scopes_from_shibmd = [
            s["text"]
            for s in data.metadata.get(issuer, {}).get("issuer_shibmd_scopes") or []
            if not s["regexp"]
        ]
        scopes_from_sho = sho
        scopes_from_eppn = [
            v.split("@", 1)[-1]
            for v in eppn
            if "@" in v
        ]
        scopes_from_fallback = (
            [config.scope_fallback]
            if config.scope_fallback
            else []
        )
        scopes = (
            scopes_from_shibmd
            or scopes_from_sho
            or scopes_from_eppn
            or scopes_from_fallback
            or []
        )

        derived_affiliations = list(
            uniquify_seq(
                epsa
                or [
                    f"{affiliation}@{scope}"
                    for scope in scopes
                    for affiliation in epa
                ]
                or []
            )
        )

        derived_epsa = derived_affiliations
        derived_vpea = (
            [
                *vpea,
                *derived_affiliations,
            ]
            or [
                f"unknown@{scope}"
                for scope in scopes
            ]
            or []
        )

        report = {
            "issuer": issuer,
            "requester": requester,
            "scopes": scopes,
            "derived_epsa": derived_epsa,
            "derived_vpea": derived_vpea,
        }
        logger.info(report)

        data.attributes[config.epsa_attribute] = derived_epsa
        data.attributes[config.vpea_attribute] = derived_vpea
        return super().process(context, data)
