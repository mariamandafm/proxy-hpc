"""Verify that an entity is allowed to access the service."""
import json
import logging

from typing import Iterable
from urllib.parse import urlencode
from satosa.exception import SATOSAError
from satosa.micro_services.base import RequestMicroService
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class AccessListError(SATOSAError):
    """Generic error."""


class AccessList():
    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.redirect_url = config.get("redirect_url")
        self.access_list = config.get("access_list")

        validators = {
            "redirect_url is set and it is a string": type(self.redirect_url) is str,
            "access_list is set and it is a list with at least one item": (
                isinstance(self.access_list, Iterable)
                and type(self.access_list) is not str
                and len(self.access_list)
            ),
        }
        if not all(validators.values()):
            log_data = {
                "message": (
                    "The configuration for this plugin is not valid. "
                    "Make sure that the following rules are met: "
                    ", ".join(validators.keys())
                ),
                "config": config,
                "validators": validators,
            }
            raise AccessListError(log_data)

    @logging_wrapper(logger)
    def process(self, context, internal_data):
        entity = self.get_entity(context, internal_data)
        if entity in self.access_list:
            logger.info("Requester {} is enabled".format(entity))
            return super().process(context, internal_data)

        logger.warning("Requester {} is not enabled".format(entity))

        data = self.collect_response_data(context, internal_data)
        query = urlencode({"data": json.dumps(data)})
        redirect_url = "{location}?{query}".format(
            location=self.redirect_url, query=query
        )
        return Redirect(redirect_url)


class IssuerAccessList(AccessList, ResponseMicroService):
    """
    Verify that an issuer is allowed to access the service.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.access_list.IssuerAccessList
    name: Issuer access list
    config:
      # The url to redirect to, if the entity is unauthorized
      redirect_url: https://example.org/access-denied

      # The list of authorized requesters
      access_list:
        - saml-issuer-entity-id
        - oidc-issuer-redirect-url
        - another-issuer-id
    ```
    """

    def get_entity(self, context, internal_data):
        return internal_data.auth_info.issuer

    def collect_response_data(self, context, internal_data):
        data = {"issuer": internal_data.auth_info.issuer}
        return data


class RequesterAccessList(AccessList, RequestMicroService):
    """
    Verify that a requester is allowed to access the service.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.access_list.RequesterAccessList
    name: Requester access list
    config:
      # The url to redirect to, if the entity is unauthorized
      redirect_url: https://example.org/access-denied

      # The list of authorized requesters
      access_list:
        - saml-requester-entity-id
        - oidc-requester-redirect-url
        - another-requester-id
    ```
    """

    def get_entity(self, context, internal_data):
        return internal_data.requester

    def collect_response_data(self, context, internal_data):
        data = {
            "requester": internal_data.requester,
            "requester_name": internal_data.requester_name,
        }
        return data
