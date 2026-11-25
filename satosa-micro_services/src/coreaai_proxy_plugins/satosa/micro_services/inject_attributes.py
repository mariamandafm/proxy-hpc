import itertools
import logging
from copy import deepcopy
from typing import Iterable

from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.config import parse_config
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))

ASSURANCE_CERTIFICATION = "urn:oasis:names:tc:SAML:attribute:assurance-certification"
SUBJECT_ID_ATTRIBUTE = "subject-id"
EMAIL_ATTRIBUTE = "mail"
EU_LOGIN_DOMAIN_ATTRIBUTE = "https://ecas.ec.europa.eu/claims/domain"


class InjectAttributesError(SATOSAError):
    pass


class InjectAttributes(ResponseMicroService):
    """
    example configuration:

    ```
    module: satosa.micro_services.inject_attributes.InjectAttributes
    name: InjectAttributes
    config:
      issuer:
        requester:
          # Disables the InjectAttributes for this issuer/requester combination.
          # Default is False
          disabled: False
          attributes:
            # The name of the attribute to inject
            - attribute: name_of_the_attribute
              # The values to inject in the attribute. They can be more than
              # one
              values: [an_attribute_value]
              # If the attribute already has value, should we overwrite them?
              # Default is False
              overwrite_values: False
              # The strategy to use for the search_for rule. Available options
              # are:
              # "all" means that rules must match
              # "any" means that at least one rule mast match
              # "always" means that attribute and its values will be always
              # injected regardless of the rules
              strategy: all
              search_for:
                  # Check if some_attribute exists
                  attribute: some_attribute
                  # Check if some_attribute with <strategy> (all or any) of the given values exists
                  attribute_values:
                    attr_name: some_attribute
                    strategy: all
                    attr_values:
                      - some_value_x
                      - some_value_y
                  # Check if any of the attributes in the list exist
                  any_attributes:
                      - some_attribute_a
                      - some_attribute_b
                  # Check if all of the attributes in the list exist
                  all_attributes:
                      - some_attribute_a
                      - some_attribute_b
                  # Check if any of the values in the list match the authenticating authority of the request
                  any_authenticating_authority:
                      - some_authority_a
                      - some_authority_b
                  # Check if all the entity categories in the list exist
                  all_entity_categories:
                      - some_entity_category_a
                      - some_entity_category_b
                  # Check if all the entity_category_support in the list exist
                  all_entity_categories_support:
                      - some_entity_category_a
                      - some_entity_category_b
                  # Check if all the assurance certifications in the list exist
                  all_assurance_certifications:
                      - some_entity_attributes_value
                  # Check if any the issuer has been registered in any of the
                  # registration authorities in the list
                  any_registration_authorities:
                      - some_registration_authority
                  # Check if the subject_id of the user in the list
                  any_subject_id:
                      - some_subject_id
                  # Check if the email of the user in the list
                  any_email:
                      - some_email
                  any_eu_login_domain:
                      - some domain
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        (_config, log_data) = validate_config(config)
        if _config is False:
            raise InjectAttributesError(log_data)

        self.config = _config

    @logging_wrapper(logger)
    def process(self, context: Context, data: InternalData) -> InternalData:
        internal_attributes = data.attributes
        requester = data.requester
        issuer = data.auth_info.issuer

        parsed_config = parse_config(self.config, issuer, requester)
        config = (
            parsed_config["by-iss-req"]
            if isinstance(parsed_config["by-iss-req"], dict)
            else parsed_config["by-req-iss"]
            if isinstance(parsed_config["by-req-iss"], dict)
            else parsed_config["by-requester"]
            if isinstance(parsed_config["by-requester"], dict)
            else parsed_config["by-issuer"]
            if isinstance(parsed_config["by-issuer"], dict)
            else {}
        )

        if config == {} or config.get("disabled"):
            return super().process(context, data)

        def adapt_search_attributes(searcher):
            def _adapter(query):
                return searcher(internal_attributes, query)

            return _adapter

        def adapt_search_internal_data(searcher):
            def _adapter(query):
                return searcher(data, query)

            return _adapter

        def adapt_search_metadata(searcher):
            def _adapter(query):
                mdstore = data.get("metadata", {})
                return searcher(mdstore, issuer, query)

            return _adapter

        search_handlers = {
            "attribute": adapt_search_attributes(search_for_attribute),
            "attribute_values": adapt_search_attributes(search_for_attribute_values),
            "any_attributes": adapt_search_attributes(search_for_any_attributes),
            "all_attributes": adapt_search_attributes(search_for_all_attributes),
            "any_subject_id": adapt_search_attributes(search_for_any_subject_id),
            "any_email": adapt_search_attributes(search_for_any_email),
            "any_eu_login_domain": adapt_search_attributes(
                search_for_any_eu_login_domain
            ),
            "any_authenticating_authority": adapt_search_internal_data(
                search_for_any_authenticating_authority
            ),
            "all_entity_categories": adapt_search_metadata(
                search_for_all_entity_categories
            ),
            "all_entity_categories_support": adapt_search_metadata(
                search_for_all_entity_categories_support
            ),
            "all_assurance_certifications": adapt_search_metadata(
                search_for_all_assurance_certifications
            ),
            "any_registration_authorities": adapt_search_metadata(
                search_for_any_registration_authority
            ),
        }

        for attribute_config in config.get("attributes", []):
            attribute_name = attribute_config.get("attribute")
            _inject_attributes = {}
            _inject_attributes[attribute_name] = attribute_config.get("values") or {}
            _strategy = (
                all
                if "all" == attribute_config.get("strategy")
                else always
                if "always" == attribute_config.get("strategy")
                else any
            )
            _search_for = attribute_config.get("search_for") or {}

            if _strategy(
                itertools.chain.from_iterable(
                    to_iterable(search_handlers[property](values))
                    for property, values in _search_for.items()
                )
            ):
                if (
                    not attribute_config.get("overwrite_values")
                    and attribute_name in internal_attributes
                ):
                    _inject_attributes[attribute_name] = (
                        internal_attributes[attribute_name]
                        + _inject_attributes[attribute_name]
                    )
                data.attributes.update(deepcopy(_inject_attributes))

                log_data = {
                    "messsage": "attributes have been injected",
                    "idp": issuer,
                    "attribute": attribute_name,
                    "values": _inject_attributes[attribute_name],
                }
                logger.debug(log_data)

        return super().process(context, data)


def to_iterable(result):
    return (
        result
        if isinstance(result, Iterable) and not isinstance(result, str)
        else [result]
    )


def search_for_attribute(attributes, value):
    return value in attributes


def search_for_attribute_values(attributes, query):
    req_attr_name = query.get("attr_name")
    req_attr_values = query.get("attr_values")
    strategy = {"all": all, "any": any}.get(query.get("strategy"))
    if not req_attr_name or not req_attr_values or not strategy:
        return False

    attr_values = attributes.get(req_attr_name) or []
    return strategy(req_val in attr_values for req_val in req_attr_values)


def search_for_any_attributes(attributes, values):
    return any(value in attributes for value in values)


def search_for_all_attributes(attributes, values):
    return all(value in attributes for value in values)


def search_for_any_authenticating_authority(internal_data, values):
    authenticating_authority = internal_data.auth_info.authority
    return authenticating_authority in values


def search_for_all_entity_categories(mdstore, issuer, values):
    entity_categories = mdstore.get(issuer, {}).get("entity_categories", [])
    return (value in entity_categories for value in values)


def search_for_all_entity_categories_support(mdstore, issuer, values):
    supported_entity_categories = mdstore.get(issuer, {}).get(
        "supported_entity_categories", []
    )
    return (value in supported_entity_categories for value in values)


def search_for_all_assurance_certifications(mdstore, issuer, values):
    assurance_certifications = mdstore.get(issuer, {}).get(
        "assurance_certifications", []
    )
    return (value in assurance_certifications for value in values)


def search_for_any_registration_authority(mdstore, issuer, values):
    registration_authority = (
        mdstore.get(issuer, {})
        .get("registration_info", {})
        .get("registration_authority", "")
    )
    return registration_authority in values


def search_for_any_subject_id(internal_attributes, values):
    subject_id_values = internal_attributes.get(SUBJECT_ID_ATTRIBUTE, [])
    return subject_id_values != [] and set(subject_id_values).issubset(values)


def search_for_any_email(internal_attributes, values):
    email_values = internal_attributes.get(EMAIL_ATTRIBUTE, [])
    return email_values != [] and set(email_values).issubset(values)


def search_for_any_eu_login_domain(internal_attributes: dict, values: list) -> bool:
    eu_login_domain_values = internal_attributes.get(EU_LOGIN_DOMAIN_ATTRIBUTE, [])
    return any(v in values for v in eu_login_domain_values)


def always(_value):
    return True


def validate_config(config):
    log_data = {
        "message": (
            "Configuration error: The configuration is "
            "either missing attributes to inject, "
            "or missing the rules and issuer list. "
            "Without these settings this plugin has nothing to do."
        ),
    }

    for issuer, issuer_config in config.items():
        for requester, requester_config in issuer_config.items():
            _config = requester_config

            if not _config.get("attributes") and not _config.get("disabled"):
                log_data["_config"] = _config
                return False, log_data

            if _config.get("disabled"):
                continue

            for attribute_config in _config.get("attributes"):
                if (
                    not attribute_config
                    or not attribute_config.get("attribute")
                    or not attribute_config.get("values")
                    or (
                        not any(
                            values
                            for property, values in attribute_config.get(
                                "search_for"
                            ).items()
                        )
                        and attribute_config.get("strategy") != "always"
                    )
                ):
                    log_data["config"] = attribute_config
                    logger.error(log_data)
                    return False, log_data

    return config, {}
