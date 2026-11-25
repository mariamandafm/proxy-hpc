"""A micro-SP just to handle the communication towards the StepUp Service for SFO."""

import functools
import json
import logging
from typing import Iterable
from typing import Mapping
from urllib.parse import urlparse

import saml2.xmldsig as ds
from saml2.authn_context import requested_authn_context
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import create_metadata_string
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED
from saml2.saml import NameID
from saml2.saml import Subject

import satosa.util as util
from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Response
from satosa.saml_util import make_saml_response


logger = logging.getLogger(__name__)


def is_loa_requirements_satisfied(accepted_loas, received_loa):
    satisfied = received_loa in accepted_loas
    return satisfied


class StepUpError(SATOSAError):
    """Generic error for this plugin."""


class StepUp(ResponseMicroService):
    """
    A micro-SP just to handle the communication towards the StepUp Service for SFO.

    Configuration option:
    - sign_alg: the algorithm that will be used for signing;
      default: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - digest_alg: the algorithm that will be used for digesting;
      default: http://www.w3.org/2001/04/xmlenc#sha256
    - mfa: a mapping between SP entity-ids and LoA settings
    - nameid_from_attribute: the attribute which value will be used as the NameID value
    - sp_config: the SP configuration passed to pysaml2

    Example configuration:

      module: coreaai_proxy_plugins.satosa.micro_services.stepup.StepUp
      name: stepup
      config:
        # the algorithm that will be used for signing
        sign_alg: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
        # the algorithm that will be used for digesting
        digest_alg: http://www.w3.org/2001/04/xmlenc#sha256

        # the attribute which value will be used as the NameID value
        nameid_from_attribute: edupersonuniqueid

        # a mapping between SP entity-ids and LoA settings
        # the required LoA will be requested from the StepUp service
        # the accepted LoAs are all the LoAs that satisfy the SP requirements
        mfa:
          some-entityid:
            required: some-loa-2
            accepted:
              - some-loa-2
              - some-loa-3
          https://sp.satosa.docker/sp.xml:
            required: urn:oasis:names:tc:SAML:2.0:ac:classes:mfa
            accepted:
              - urn:oasis:names:tc:SAML:2.0:ac:classes:mfa

        sp_config:
          organization:
            display_name: StepUp Microservice
            name: StepUp Microservice
            url: https://stepup-microservice.example.org

          preferred_binding:
              single_sign_on_service:
              - urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
              - urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST

          contact_person:
          - contact_type: technical
            email_address: technical@example.com
            given_name: Technical
          - contact_type: support
            email_address: support@example.com
            given_name: Support

          metadata:
            local:
            - stepup-service.xml

          key_file: pki/stepup.key
          cert_file: pki/stepup.crt
          want_assertions_or_response_signed: yes

          entityid: <base_url>/<name>/stepup.xml
          service:
            sp:
              name_id_format: ''
              allow_unsolicited: true
              want_response_signed: true
              authn_requests_signed: true
              endpoints:
                assertion_consumer_service:
                - [<base_url>/<name>/acs/post, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
                - [<base_url>/<name>/acs/redirect, 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)

        mfa_is_a_mapping = isinstance(config.get("mfa"), Mapping)
        mfa_has_at_least_one_entry = mfa_is_a_mapping and len(config["mfa"])
        mfa_entityid_is_string = mfa_is_a_mapping and all(
            type(entityid) is str for entityid in config["mfa"].keys()
        )
        mfa_loa_settings_is_a_mapping = mfa_is_a_mapping and all(
            isinstance(loa_settings, Mapping)
            for entityid, loa_settings in config["mfa"].items()
        )
        mfa_loa_settings_has_required_field = mfa_loa_settings_is_a_mapping and all(
            "required" in loa_settings.keys() and type(loa_settings["required"]) is str
            for entityid, loa_settings in config["mfa"].items()
        )
        mfa_loa_settings_has_accepted_field = mfa_loa_settings_is_a_mapping and all(
            "accepted" in loa_settings.keys()
            and isinstance(loa_settings["accepted"], Iterable)
            and all(type(loa) is str for loa in loa_settings["accepted"])
            for entityid, loa_settings in config["mfa"].items()
        )
        mfa_loa_required_is_included_in_accepted = (
            mfa_loa_settings_has_accepted_field
            and mfa_loa_settings_has_required_field
            and all(
                loa_settings["required"] in loa_settings["accepted"]
                for entityid, loa_settings in config["mfa"].items()
            )
        )
        nameid_from_attribute_is_a_string = (
            type(config.get("nameid_from_attribute")) is str
        )
        sign_alg_is_a_string = type(config.get("sign_alg", "")) is str
        digest_alg_is_a_string = type(config.get("digest_alg", "")) is str

        validators = {
            "mfa_is_a_mapping": mfa_is_a_mapping,
            "mfa_has_at_least_one_entry": mfa_has_at_least_one_entry,
            "mfa_entityid_is_string": mfa_entityid_is_string,
            "mfa_loa-settings_is_a_mapping": mfa_loa_settings_is_a_mapping,
            "mfa_loa-settings_has_required_field": mfa_loa_settings_has_required_field,
            "mfa_loa-settings_has_accepted_field": mfa_loa_settings_has_accepted_field,
            "mfa_loa_required_is_included_in_accepted": mfa_loa_required_is_included_in_accepted,
            "nameid_from_attribute_is_a_string": nameid_from_attribute_is_a_string,
            "sign_alg_is_a_string": sign_alg_is_a_string,
            "digest_alg_is_a_string": digest_alg_is_a_string,
        }

        if not all(validators.values()):
            error_context = {
                "message": (
                    "The configuration for this plugin is not valid. "
                    "Make sure that the following rules are met: "
                    ", ".join(rule.replace("_", " ") for rule in validators.keys())
                ),
                "validators": validators,
            }
            raise StepUpError(error_context)

        self.mfa = config["mfa"]
        self.sign_alg = config.get("sign_alg", ds.SIG_RSA_SHA256)
        self.digest_alg = config.get("digest_alg", ds.DIGEST_SHA256)
        self.nameid_from_attribute = config.get("nameid_from_attribute")

        sp_config = json.loads(
            json.dumps(config["sp_config"])
            .replace("<base_url>", self.base_url)
            .replace("<name>", self.name)
        )
        sp_conf = SPConfig().load(sp_config, metadata_construction=False)
        self.sp = Saml2Client(config=sp_conf)

        logger.info("StepUp Authentication is active")

    def process(self, context, internal_response):
        entityid = internal_response.requester
        loa_received = internal_response.auth_info.auth_class_ref
        loa_settings = self.mfa.get(entityid)
        nameid_value = "".join(
            internal_response.attributes.get(self.nameid_from_attribute, [])
        )

        is_mfa_needed = loa_settings and not is_loa_requirements_satisfied(
            loa_settings["accepted"], loa_received
        )
        if is_mfa_needed:
            return self._send_authn_to_stepup_service(
                context, internal_response, loa_settings["required"], nameid_value
            )

        return super().process(context, internal_response)

    def _send_authn_to_stepup_service(
        self, context, internal_response, loa, nameid_value
    ):
        entityid = self.sp.metadata.identity_providers()[0]
        authn_context = requested_authn_context(loa, comparison="exact")
        relay_state = util.rndstr()
        sign = self.sp.config.getattr("authn_requests_signed") or bool(
            self.sp.config.key_file and self.sp.config.cert_file
        )

        name_id = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=nameid_value)
        subject = Subject(name_id=name_id)

        kwargs = {
            "sign_alg": self.sign_alg,
            "digest_alg": self.digest_alg,
            "sigalg": self.sign_alg,
            "subject": subject,
            "requested_authn_context": authn_context,
        }

        try:
            binding, destination = self.sp.pick_binding(
                service="single_sign_on_service",
                descr_type="idpsso",
                entity_id=entityid,
            )
            req_id, ht_args = self.sp.prepare_for_authenticate(
                entityid=entityid,
                binding=binding,
                response_binding=binding,
                relay_state=relay_state,
                sign=sign,
                **kwargs,
            )
        except Exception as e:
            error_context = {
                "message": "Failed to construct the AuthnRequest",
                "entityid": entityid,
                "name_id": name_id,
                "params": kwargs,
                "sign": sign,
            }
            raise StepUpError(error_context) from e

        context.state[self.name] = {
            "relay_state": relay_state,
            "internal_data": internal_response.to_dict(),
        }
        return make_saml_response(binding, ht_args)

    def _handle_authn_response(self, context, binding):
        internal_data = context.state[self.name]["internal_data"]
        internal_response = InternalData.from_dict(internal_data)
        entityid = internal_response.requester
        loa_settings = self.mfa[entityid]

        try:
            authn_response = self.sp.parse_authn_request_response(
                context.request["SAMLResponse"], binding
            )
        except Exception as e:
            error_context = {
                "message": "Invalid AuthnResponse",
                "entityid": entityid,
                "request": context.request.get("SAMLResponse"),
                "context": context,
            }
            raise StepUpError(error_context) from e

        authn_info = authn_response.authn_info()[0]
        auth_class_ref = authn_info[0]
        loa_received = auth_class_ref

        is_mfa_satisfied = is_loa_requirements_satisfied(
            loa_settings["accepted"], loa_received
        )
        if not is_mfa_satisfied:
            error_context = {
                "message": "Second factor authentication failed",
                "entityid": entityid,
                "config": loa_settings,
                "received LoA": loa_received,
            }
            raise StepUpError(error_context)

        internal_response.auth_info.auth_class_ref = loa_received
        del context.state[self.name]
        return super().process(context, internal_response)

    def _metadata_endpoint(self, context):
        metadata_string = create_metadata_string(
            None, self.sp.config, 4, None, None, None, None, None
        ).decode("utf-8")
        return Response(metadata_string, content="text/xml")

    def register_endpoints(self):
        url_map = []

        # acs endpoints
        sp_endpoints = self.sp.config.getattr("endpoints", "sp")
        for endp, binding in sp_endpoints["assertion_consumer_service"]:
            parsed_endp = urlparse(endp)
            url_map.append(
                (
                    "^{endpoint}$".format(endpoint=parsed_endp.path[1:]),
                    functools.partial(self._handle_authn_response, binding=binding),
                )
            )

        # metadata endpoint
        parsed_entity_id = urlparse(self.sp.config.entityid)
        url_map.append(
            (
                "^{endpoint}".format(endpoint=parsed_entity_id.path[1:]),
                self._metadata_endpoint,
            )
        )

        return url_map
