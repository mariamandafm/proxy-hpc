from functools import lru_cache
from logging import getLogger as get_logger
from json import loads as _load_json_from_string

from typing import Mapping
from typing import Sequence

from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.errors import Error as _Error

from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))


class Error(_Error):
    ...


class Config(TableConfig):
    attribute_email: str
    attribute_iuids: str
    datafile: str


class IUIDsByEmail(ResponseMicroService):
    """Inject IUIDs looked up by email from a datafile.

    For each value of the configured email attribute, the email is looked up in a
    JSON export (a file mapping email to a list of IUIDs) and any matches are
    appended to the configured IUID attribute.

    The configuration is a list of entries resolved per requester and issuer; a
    catch-all entry (no ``requester``/``issuer``) is REQUIRED as the fallback.
    Each entry needs ``attribute_email``, ``attribute_iuids`` and ``datafile``,
    and may set ``skip`` to pass the request through unchanged.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.iuids_by_email.IUIDsByEmail
    name: IUIDsByEmail
    config:
      # required catch-all fallback
      - skip: true
        attribute_email: email
        attribute_iuids: identifiers
        datafile: users_export_Example.json
      # look up IUIDs for this requester/issuer pair
      - requester: https://sp.example.com
        issuer: https://idp.example.com
        attribute_email: email
        attribute_iuids: identifiers
        datafile: users_export_Example.json
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    attribute_email=c["attribute_email"],
                    attribute_iuids=c["attribute_iuids"],
                    datafile=c["datafile"],
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

        data_exported = load_exported_data(config.datafile)

        emails = data.attributes.get(config.attribute_email, [])
        iuids = data.attributes.get(config.attribute_iuids, [])

        matched_entries = [
            {
                "email": email,
                "iuids": data_exported[email],
            }
            for email in emails
            if email in data_exported.keys()
        ]
        matched_iuids = [iuid for entry in matched_entries for iuid in entry["iuids"]]
        merged_iuids = [*iuids, *matched_iuids]

        report = {
            "emails": emails,
            "matched_entries": matched_entries,
            "merged_iuids": merged_iuids,
        }
        logger.info(report)

        if merged_iuids:
            data.attributes[config.attribute_iuids] = merged_iuids
        return super().process(context, data)


@lru_cache(maxsize=10)
def load_exported_data(datafile: str):
    with open(datafile) as fp:
        export_raw = fp.read()
        export_json = _load_json_from_string(export_raw)
        return export_json
