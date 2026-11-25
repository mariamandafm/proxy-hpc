"""
A plugin to configure the NameID value and format.

You can use this plugin to:
- set the NameID format
- set the NameID value by combining specific attributes
- hash the NameID value
- add scope to the NameID value
- or a combination of the above
selectively for some SPs or requesters
"""

import hashlib
import logging
from typing import Iterable
from typing import Mapping

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class NameIDProcessorError(SATOSAError):
    """Generic error for this module."""


class NameIDProcessor(ResponseMicroService):
    """
    A plugin to configure the NameID value and format.

    You can use this plugin to:
    - set the NameID format
    - set the NameID value by combining specific attributes
    - hash the NameID value
    - add scope to the NameID value
    - or a combination of the above
    selectively for some SPs or requesters

    Example configuration:

      module: coreaai_proxy_plugins.satosa.micro_services.nameid_processor.NameIDProcessor
      name: NameIDProcessor
      config:

        # the empty string key is used to denote the default settings, by default
        # - do not set the NameID format
        # - do not set the NameID value
        # - do not hash the NameID value
        # - do not scope the NameID value
        # this is equivalent to omitting the "" key,
        # or setting it with the following configuration:
        "":
          nameid-format:
          attributes: []
          hash: {}
          scope:

        # for the SP with entity-id "sp-entity-id"
        # - set the NameID format to be persistent
        # - set the NameID value by concatenating the values of attributes
        #   "attribute-a" and "attribute-b", in that order
        #   note: attributes are specified by their internal name
        # - hash the NameID value with SHA-512 and the given salt
        #   note: it is required to set a salt to hash a value
        # - scope the NameID value with the given scope
        sp-entity-id:
          nameid-format: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
          attributes:
            - attribute-a
            - attribute-b
          scope: @example.com
          hash:
            alg: sha512
            salt: abcdefgh1234567890
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)

        validators = {
            "every_nameid-format_is_a_string": all(
                type(properties["nameid-format"]) is str
                for requestter, properties in config.items()
                if properties.get("nameid-format")
            ),
            "all_attributes_are_an_iterable_and_not_a_string": all(
                isinstance(properties["attributes"], Iterable)
                and not type(properties["attributes"]) is str
                for requestter, properties in config.items()
                if properties.get("attributes")
            ),
            "every_scope_is_a_string_starting_with_@": all(
                type(properties["scope"]) is str and properties["scope"].startswith("@")
                for requestter, properties in config.items()
                if properties.get("scope")
            ),
            "every_hash_has_salt_and_salt_is_a_string": all(
                isinstance(properties["hash"], Mapping)
                and type(properties["hash"].get("salt")) is str
                for requestter, properties in config.items()
                if properties.get("hash")
            ),
            "every_hash_alg_is_a_string": all(
                isinstance(properties["hash"], Mapping)
                and type(properties["hash"].get("alg")) is str
                for requestter, properties in config.items()
                if properties.get("hash")
            ),
            "at_least_one_entry_has_nameid-format_or_attributes_or_scope_or_hash": any(
                properties.get("nameid-format")
                or properties.get("attributes")
                or properties.get("scope")
                or properties.get("hash")
                for requestter, properties in config.items()
            ),
        }

        if not all(validators.values()):
            error_context = {
                "message": (
                    "The configuration for this plugin is not valid. "
                    "Make sure that the following rules are met: "
                    ", ".join(rule.replace("_", " ") for rule in validators.keys())
                ),
                "validators": validators,
                "config": config,
            }
            raise NameIDProcessorError(error_context)

        defaults = {"nameid-format": "", "attributes": [], "scope": "", "hash": {}}

        config = {
            requester: {
                "nameid-format": (
                    options.get("nameid-format") or defaults["nameid-format"]
                ),
                "attributes": options.get("attributes") or defaults["attributes"],
                "scope": options.get("scope") or defaults["scope"],
                "hash": options.get("hash") or defaults["hash"],
            }
            for requester, options in config.items()
        }

        self.default_nameid_properties = config.pop("", defaults)
        self.sp_to_nameid_properties = config

    @logging_wrapper(logger)
    def process(self, context, internal_data):
        requester = internal_data.requester
        config = self.sp_to_nameid_properties.get(
            requester, self.default_nameid_properties
        )

        nameid_format = config["nameid-format"]
        attributes = config["attributes"]
        hash_conf = config["hash"]
        scope = config["scope"]

        if nameid_format:
            internal_data.subject_type = nameid_format

        if attributes:
            value_from_attributes = "".join(
                attr_value
                for attr_name in attributes
                for attr_value in internal_data.attributes.get(attr_name) or []
            )

            if value_from_attributes:
                internal_data.subject_id = value_from_attributes
            else:
                error_context = {
                    "message": "Could not collect any attributes",
                    "attributes": attributes,
                }
                raise NameIDProcessorError(error_context)

        if hash_conf:
            hasher = create_hasher(
                hash_conf["salt"], alg=hash_conf.get("alg", "sha512")
            )
            seed = internal_data.subject_id
            internal_data.subject_id = hasher(seed)

        if scope:
            internal_data.subject_id = "{id}{scope}".format(
                id=internal_data.subject_id, scope=scope
            )

        return super().process(context, internal_data)


def create_hasher(salt, alg="sha512"):
    if type(salt) is not bytes:
        salt = salt.encode("utf-8")

    def _hasher(value):
        if type(value) is not bytes:
            value = value.encode("utf-8")

        hasher = hashlib.new(alg)
        hasher.update(salt)
        hasher.update(value)
        return hasher.hexdigest()

    return _hasher
