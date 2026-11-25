import logging
from copy import deepcopy
from typing import Iterable

from satosa.micro_services.base import ResponseMicroService
from satosa.exception import SATOSAError

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))
EWP_ADMIN_EXT_VALUE = "urn:geant:erasmuswithoutpaper.eu:ewp:admin"
EWP_ADMIN_INT_NS = "urn:geant:myacademicid.org:ewp"
EWP_ADMIN_INT_ATTR = "_ewp_admin"


class EwpAdminError(SATOSAError):
    """Generic error for this module"""


class EWPAdminProcessor(ResponseMicroService):
    """Derive the internal EWP admin attribute from an IdP entitlement.

    When the IdP asserts the ``urn:geant:erasmuswithoutpaper.eu:ewp:admin``
    entitlement, set the internal ``_ewp_admin`` attribute to one
    ``urn:geant:myacademicid.org:ewp:<schacHomeOrganization>:admin`` value per
    home organization. Response microservice; takes no config.

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.ewp_admin.EWPAdminProcessor
    name: EWPAdminProcessor
    ```
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.internal_to_saml = {
            internal_name: protocols.get("saml", [])
            for internal_name, protocols in internal_attributes["attributes"].items()
        }

    def get_val_of_saml_attr(self, attributes, saml_attr):
        return attributes.get(
            [
                int_attr
                for int_attr, saml_attrs in self.internal_to_saml.items()
                if saml_attr in saml_attrs
            ].pop(),
            [],
        )

    @logging_wrapper(logger)
    def process(self, context, data):
        epes = self.get_val_of_saml_attr(data.attributes, "eduPersonEntitlement")
        shos = self.get_val_of_saml_attr(data.attributes, "schacHomeOrganization")

        if EWP_ADMIN_EXT_VALUE in epes:
            values = [
                f"{EWP_ADMIN_INT_NS}:{sho}:admin"
                for sho in shos
            ]
            data.attributes[EWP_ADMIN_INT_ATTR] = values

        return super().process(context, data)


class EWPAdminGenerator(ResponseMicroService):
    """Expose the internal EWP admin attribute as an RP entitlement.

    When the internal ``_ewp_admin`` attribute is present, append its values to
    the entitlement attribute sent to the RP. Response microservice; takes no
    config. Pairs with EWPAdminProcessor, which produces ``_ewp_admin``.

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.ewp_admin.EWPAdminGenerator
    name: EWPAdminGenerator
    ```
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.internal_to_saml = {
            internal_name: protocols.get("saml", [])
            for internal_name, protocols in internal_attributes["attributes"].items()
        }

    @logging_wrapper(logger)
    def process(self, context, data):
        attr_name = [
            int_attr
            for int_attr, saml_attrs in self.internal_to_saml.items()
            if "eduPersonEntitlement" in saml_attrs
        ].pop()

        if EWP_ADMIN_INT_ATTR in data.attributes:
            data.attributes[attr_name] = (
                data.attributes.get(attr_name, []) + data.attributes[EWP_ADMIN_INT_ATTR]
            )

        return super().process(context, data)
