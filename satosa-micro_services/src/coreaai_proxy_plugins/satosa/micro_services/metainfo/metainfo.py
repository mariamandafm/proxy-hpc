"""Extract metadata information for the requester and issuer."""
from logging import getLogger as get_logger
from typing import List
from typing import Mapping
from typing import Sequence

from satosa.micro_services.base import ResponseMicroService
from satosa.micro_services.base import RequestMicroService
from satosa.context import Context
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper

from .collectors import collect_oidc_entity_metadata
from .collectors import collect_saml_entity_metadata

import re

logger = ExtraLogger(get_logger(__name__))

KEY_STATE = "MetaInfoService"
KEY_ISSUER_METADATA = "metadata_store"
KEY_SAML_REQUESTER_METADATA = "metadata_store"
KEY_OIDC_REQUESTER_METADATA = "requester_metadata"
UUID4HEX = re.compile(
    r"^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z", re.I
)


class Config(TableConfig):
    metadata_field_names: List[str]


def is_oidc_client(entity_id):
    result = entity_id.startswith("APP-") or bool(UUID4HEX.match(entity_id))
    return result


def collect_entity_metadata(mdstore, entity_id, metadata_field_names):
    entity_metadata = (
        {}
        if not mdstore
        else collect_oidc_entity_metadata(mdstore, entity_id, metadata_field_names)
        if is_oidc_client(entity_id)
        else collect_saml_entity_metadata(mdstore, entity_id, metadata_field_names)
    )
    return entity_metadata


def update_metadata_with_entity(mdstore, metadata, entity_id, metadata_field_names):
    entity_metadata = collect_entity_metadata(mdstore, entity_id, metadata_field_names)
    updated_metadata = (
        {**metadata, entity_id: entity_metadata} if entity_metadata else metadata
    )
    return updated_metadata


class _MetaInfoService:
    """
    Extract metadata info for the requester (on request) and the issuer (on response)
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)
        table_configs: Sequence[Config] = [
            Config(
                metadata_field_names=c.get("metadata_field_names", []),
                requester=c.get("requester"),
                issuer=c.get("issuer"),
                skip=c.get("skip"),
            )
            for c in config
        ]
        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchical_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, internal_data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, internal_data)

        metadata = self.extract_metadata_state(context.state)
        entity_id = self.get_entity_id(internal_data)
        mdstore = self.get_metadata_store(context, entity_id)

        metadata_new = update_metadata_with_entity(
            mdstore=mdstore,
            metadata=metadata,
            entity_id=entity_id,
            metadata_field_names=config.metadata_field_names
        )

        internal_data.metadata = metadata_new
        self.update_metadata_state(context.state, metadata_new)
        return super().process(context, internal_data)


class MetaInfoRequester(_MetaInfoService, RequestMicroService):
    """
    Extract metadata info for the requester.

    Example configuration:

      ```yaml
      module: satosa.micro_services.metainfo.MetaInfoRequester
      name: MetaInfoRequester
      ```
    """

    def extract_metadata_state(self, state):
        metadata = {}
        return metadata

    def update_metadata_state(self, state, metadata):
        state[KEY_STATE] = {"metadata": metadata}

    def get_metadata_store(self, context, entity_id):
        md = context.get_decoration(
            KEY_OIDC_REQUESTER_METADATA
            if is_oidc_client(entity_id)
            else KEY_SAML_REQUESTER_METADATA
        )
        return md

    def get_entity_id(self, internal_data):
        entity_id = internal_data.requester
        return entity_id


class MetaInfoIssuer(_MetaInfoService, ResponseMicroService):
    """
    Extract metadata info for the issuer.

    Example configuration:

      ```yaml
      module: satosa.micro_services.metainfo.MetaInfoIssuer
      name: MetaInfoIssuer
      ```
    """

    def extract_metadata_state(self, state):
        metadata = state.pop(KEY_STATE, {}).get("metadata", {})
        return metadata

    def update_metadata_state(self, state, metadata):
        pass

    def get_metadata_store(self, context, entity_id):
        md = context.get_decoration(KEY_ISSUER_METADATA)
        return md

    def get_entity_id(self, internal_data):
        entity_id = internal_data.auth_info.issuer
        return entity_id
