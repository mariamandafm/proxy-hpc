"""
A plugin to allow access to services based on user entitlements.
"""

import base64
import logging
from json import dumps as serialize_to_json
from typing import Mapping

from aarc_entitlement import G069 as _parse_aarc_entitlement
from aarc_entitlement import Error as _Aarc_entitlement_Error

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


def parse_aarc_requirement(requirement):
    obj = _parse_aarc_entitlement(requirement)
    return obj


def parse_aarc_entitlement(entitlement):
    obj = _parse_aarc_entitlement(entitlement)
    return obj


class AccessPerVOError(SATOSAError):
    pass


class ServiceAccessPerVO(ResponseMicroService):
    """
    A plugin to allow access to services based on user entitlements.

    The entitlements show to which VOs the user belongs to. The VOs are mapped to
    services. If the user belongs to a VO that can access the target service then the
    flow continues after the entitlements have been filtered.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.ServiceAccessPerVO
    name: access-per-vo
    config:
      # redirect to this URL if authorization fails
      error_url: https://webapp.example.org/error

      # internal attribute name that holds the entitlement information
      entitlements_attribute: epe

      # whether entitlements should be filtered
      filter_entitlements: false

      # a list of services for which to skip any access checks.
      # notice that to skip the access-requirements checks for a service
      # no requirements must be set; it is not enough to be in the skiplist.
      service_access_requirements_skiplist:
        - service-a
        - service-b

      # a mapping between service entityIDs to AARC entitlement requirements
      service_access_requirements:
        service-accessible-by-members-of-vo-x:
          - urn:ns_id:delegated_ns:x
        service-accessible-by-members-of-vo-y-group-v-or-vo-y-group-z-group-w:
          - urn:ns_id:delegated_ns:vo-y:v
          - urn:ns_id:delegated_ns:vo-y:z:w
        service-accessible-by-the-managers-of-vo-y-group-v:
          - urn:ns_id:delegated_ns:y:v:role=manager

      # base URL of the service that manages membership and entitlement information
      # will be used to construct URL to VO/group registration pages
      registrar_url_base: https://mms.example.org

      # XXX FIXME this is actually a presentational concern and should be moved away
      # a mapping of service entityIDs to (optional) error properties:
      # - message: the message to be displayed
      # - with_groups: whether the VOs with access to the service should be presented
      error_per_service:
        service-x:
            message: "an error occured"
            with_groups: false
        service-y:
            with_groups: true
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        error_url = config.get("error_url")
        entitlements_attribute = config.get("entitlements_attribute")
        filter_entitlements = config.get("filter_entitlements")
        registrar_url_base = config.get("registrar_url_base")
        error_per_service = config.get("error_per_service") or {}
        service_access_requirements_skiplist = (
            config.get("service_access_requirements_skiplist") or []
        )

        service_access_requirements_raw = config.get("service_access_requirements")
        service_access_requirements_maps_str_to_list_of_str = (
            isinstance(service_access_requirements_raw, Mapping)
            and all(
                isinstance(service, str)
                and isinstance(requirements, list)
                and all(
                    isinstance(requirement, str)
                    for requirement in (requirements or [])
                )
                for service, requirements in service_access_requirements_raw.items()
            )
        )
        service_access_requirements = (
            service_access_requirements_maps_str_to_list_of_str
            and {
                service: [
                    parse_aarc_requirement(requirement)
                    for requirement in requirements
                ]
                for service, requirements in service_access_requirements_raw.items()
            }
        )
        service_access_requirements_have_duplicate_entries = (
            service_access_requirements
            and any(
                len(requirements) == len(set(requirements))
                for service, requirements in service_access_requirements.items()
            )
        )

        validators = {
            "error_url is a string": isinstance(error_url, str),
            "registrar_url_base is a string": isinstance(error_url, str),
            "entitlements_attribute is a string": (
                isinstance(entitlements_attribute, str)
            ),
            "filter_entitlements is a boolean": (
                isinstance(filter_entitlements, bool)
            ),
            "service_access_requirements_skiplist is a list of strings": all(
                isinstance(service, str)
                for service in service_access_requirements_skiplist
            ),
            "error_per_service maps str to members of str and bool": (
                isinstance(error_per_service, Mapping)
                and all(
                    isinstance(service, str)
                    and isinstance(error_conf, Mapping)
                    and isinstance(error_conf.get("message"), (str, type(None)))
                    and isinstance(error_conf.get("with_groups"), (bool, type(None)))
                    for service, error_conf in error_per_service.items()
                )
            ),
            "service_access_requirements maps str to list of str": (
                service_access_requirements_maps_str_to_list_of_str
            ),
            "service_access_requirements have duplicate entries": (
                service_access_requirements_have_duplicate_entries
            ),
        }
        if not all(validators.values()):
            log_data = {
                "message": " ".join(
                    [
                        "The configuration for this plugin is not valid.",
                        "Make sure that the following rules are met:",
                        ", ".join(validators.keys()),
                    ]
                ),
                "validators": validators,
                "config": config,
            }
            raise AccessPerVOError(log_data)

        self.error_url = error_url
        self.entitlements_attribute = entitlements_attribute
        self.filter_entitlements = filter_entitlements
        self.registrar_url_base = registrar_url_base
        self.error_per_service = error_per_service
        self.service_access_requirements = service_access_requirements
        self.service_access_requirements_skiplist = service_access_requirements_skiplist

    @logging_wrapper(logger)
    def process(self, context, data):
        service = data.requester
        service_display_name = data.metadata.get(service, {}).get("display_name")
        service_show_groups = self.error_per_service.get(service, {}).get("with_groups")
        service_error_message = self.error_per_service.get(service, {}).get("message")

        service_requirements = self.service_access_requirements.get(service) or []
        is_service_skipped = (
            not service_requirements
            and service in self.service_access_requirements_skiplist
        )

        user_entitlements = data.attributes.get(self.entitlements_attribute) or []
        user_non_aarc_entitlements = []
        user_aarc_entitlements = {}
        for vo_urn in user_entitlements:
            try:
                vo_obj = parse_aarc_entitlement(vo_urn)
            except _Aarc_entitlement_Error as e:
                user_non_aarc_entitlements.append(vo_urn)
            else:
                user_aarc_entitlements.update({vo_urn: vo_obj})

        user_entitlements_with_service_access = {
            user_vo_urn
            for user_vo_urn, user_vo_obj in user_aarc_entitlements.items()
            if any(
                user_vo_obj.satisfies(requirement)
                for requirement in service_requirements
            )
        }

        user_can_access_service = bool(
            is_service_skipped
            or user_entitlements_with_service_access
        )

        error_data = {
            "service": service,
            "service_name": service_display_name,
            "message": service_error_message,
            "groups": [
                {
                    "req_urn": repr(requirement),
                    "req_vo_name": requirement.group,
                    "req_vo_groups": requirement.subgroups,
                    "redirect_url": "{base}?vo={vo_name}{group}".format(
                        base=self.registrar_url_base,
                        vo_name=requirement.group,
                        group=(
                            "&group={}".format(":".join(requirement.subgroups))
                            if requirement.subgroups
                            else ""
                        ),
                    ),
                }
                for requirement in service_requirements
                if service_show_groups
            ],
        }

        report = {
            "message": "Service access per VO status",
            "service": service,
            "user_can_access_service": user_can_access_service,
        }
        debug_report = {
            "user_entitlements": user_entitlements,
            "user_entitlements_with_service_access": user_entitlements_with_service_access,
            "is_service_skipped": is_service_skipped,
            "error_data": error_data,
        }

        logger.info(report)
        logger.debug(debug_report)

        if not user_can_access_service:
            data_json = serialize_to_json(error_data)
            data_b64 = base64.urlsafe_b64encode(data_json.encode("utf-8"))
            data_path = data_b64.decode("utf-8")
            redirect_url = "{location}/{path}".format(
                location=self.error_url, path=data_path
            )
            return Redirect(redirect_url)

        if self.filter_entitlements and not is_service_skipped:
            new_user_entitlements = [
                *user_non_aarc_entitlements,
                *user_entitlements_with_service_access,
            ]
            data.attributes[self.entitlements_attribute] = new_user_entitlements

        return super().process(context, data)
