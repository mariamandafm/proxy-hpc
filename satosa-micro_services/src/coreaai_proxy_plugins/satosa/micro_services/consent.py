"""
A consent module for the satosa proxy
"""
import json
import logging
from base64 import urlsafe_b64encode
from hashlib import sha512 as hash_sha512
from json import dumps as serialize_as_json

from jwkest.jwk import RSAKey
from jwkest.jwk import rsa_load
from jwkest.jws import JWS

import requests
from requests.exceptions import ConnectionError

from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers import iso3166
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))

STATE_KEY = "CONSENT"


class UnexpectedResponseError(Exception):
    pass


class Consent(ResponseMicroService):
    """Collect user consent before releasing attributes to the requester.

    Response microservice. On each response it computes a consent id from the
    requester, the attribute names and the authorizations, and asks an external
    User Info Service whether that consent already exists:

    - if it does, the released attributes are filtered to the consented set and
      the pipeline continues;
    - if it does not (or ``enforce_consent`` is set), the user is redirected to
      the User Info Service to give consent, returning via the registered
      ``consent/handle_consent`` endpoint.

    If the User Info Service is unreachable, no attributes are released.

    Configuration is keyed by ``default`` (or ``""``) with optional per-IdP
    (issuer) and per-SP (requester) overrides; an SP override wins over an IdP
    override. Each entry accepts:

    - ``api_url`` — base URL of the User Info Service (required)
    - ``redirect_url`` — base URL the user is redirected to for consent (required)
    - ``sign_key`` — path to the RSA private key used to sign consent requests
      (required)
    - ``enforce_consent`` — always ask the user, skipping the existing-consent
      check (default ``false``)
    - ``authorizations_state_key`` — state key holding the authorizations to
      include in the consent id
    - ``services_to_country_code`` — map of requester to ISO-3166 country code
    - ``services_marked_as_adequate_level_of_data_protection`` — requesters
      treated as having an adequate level of data protection
    - ``virtual_countries`` — extra country code/name pairs for display
    - ``services_agreed_to_tou`` — requesters that have agreed to the terms of use
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

        self.locked_attr = None
        if "user_id_to_attr" in internal_attributes:
            self.locked_attr = internal_attributes["user_id_to_attr"]

        self.endpoint = "/handle_consent"

    def _parse_config(self, config, context, data):
        _config = config

        try:
            if 'default' in _config and "" in _config:
                msg = """Use either 'default' or "" in config but not both"""
                logger.error(msg)
                raise KeyError(msg)

            if "" in _config:
                _config['default'] = _config.pop("")

            if 'default' not in _config:
                msg = "No default configuration is present"
                logger.error(msg)
                raise KeyError(msg)
        except KeyError as err:
            logger.error("Caught exception: {}".format(str(err)))
            return super().process(context, data)

        config = _config['default']

        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
        except KeyError as err:
            logger.error("Unable to identify the requester")
            return super().process(context, data)

        # Find the entityID for the IdP that issued the assertion
        try:
            idpEntityID = data.to_dict()['auth_info']['issuer']
        except KeyError as err:
            logger.error("Unable to identify the target")
            return super().process(context, data)

        if idpEntityID in self.config:
            config = self.config[idpEntityID]
            logger.debug("Found configuration for the target: {}".format(idpEntityID))

        # Examine our configuration to determine if there is a per-SP configuration.
        # An SP configuration overrides an IdP configuration when there is a conflict.
        if spEntityID in self.config:
            config = self.config[spEntityID]
            logger.debug("Found configuration for the requester: {}".format(spEntityID))

        logger.debug("Using configuration {}".format(config))

        return config

    def _handle_consent_response(self, context):
        """
        Endpoint for handling User Info Service response
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: response context
        :return: response
        """

        logger.bind("session_id", context.state.session_id)
        logger.info("Continue processing")

        consent_state = context.state[STATE_KEY]
        saved_resp = consent_state["internal_resp"]
        internal_data = InternalData.from_dict(saved_resp)

        config = self._parse_config(self.config, context, internal_data)
        if not config:
            logger.info("Empty configuration found. Skipping.")
            return super().process(context, internal_data)

        authorizations_state_key = config.get("authorizations_state_key")
        authorizations = context.state.get(authorizations_state_key) or []

        services_to_country_code = config.get("services_to_country_code") or {}
        services_marked_as_alodp = config.get("services_marked_as_adequate_level_of_data_protection") or {}
        virtual_countries = config.get("virtual_countries") or {}

        country_code = services_to_country_code.get(internal_data.requester)
        country_name = iso3166.get_country_name_from_code(
            country_code, extra=virtual_countries
        )
        service_has_alodp = has_service_alodp(
            internal_data.requester, country_code, services_marked_as_alodp
        )

        hash_id = generate_consent_id(
            internal_data.requester,
            internal_data.attributes,
            authorizations=authorizations,
            country_code=country_code,
            country_name=country_name,
            has_alodp=service_has_alodp,
        )

        api_url = config["api_url"]

        try:
            consent_attributes = verify_consent(api_url, hash_id)
        except ConnectionError as e:
            logger.error("User Info service is unreachable: {}".format(str(e)))

            # Send internal_data without any attributes
            consent_attributes = None

        if consent_attributes is None:
            logger.info("Confirmation was not given")
            # If confirmation was not given, then don't send any attributes
            consent_attributes = []
        else:
            logger.info("Confirmation was given")

        internal_data.attributes = filter_items_exist(
            internal_data.attributes,
            consent_attributes
        )
        return self._end_consent(context, internal_data)

    def _end_consent(self, context, internal_data):
        """
        Clear the state for confirmation and end the confirmation step

        :type context: satosa.context.Context
        :type internal_data: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: response context
        :param internal_data: the response
        :return: response
        """
        context.state.pop(STATE_KEY, None)
        return super().process(context, internal_data)

    @logging_wrapper(logger)
    def process(self, context, internal_data):
        """
        Manage confirmation and attribute filtering

        :type context: satosa.context.Context
        :type internal_data: satosa.internal.InternalData
        :rtype: satosa.response.Response

        :param context: response context
        :param internal_data: the response
        :return: response
        """

        context.state[STATE_KEY] = context.state.get(STATE_KEY, {})

        config = self._parse_config(self.config, context, internal_data)
        if not config:
            logger.error("Empty configuration found.")
            return super().process(context, internal_data)

        enforce_consent = config.get("enforce_consent", False)

        authorizations_state_key = config.get("authorizations_state_key")
        authorizations = context.state.get(authorizations_state_key) or []

        services_agreed_to_tou = config.get("services_agreed_to_tou") or []
        service_has_agreed_to_tou = internal_data.requester in services_agreed_to_tou

        services_to_country_code = config.get("services_to_country_code") or {}
        services_marked_as_alodp = config.get("services_marked_as_adequate_level_of_data_protection") or {}
        virtual_countries = config.get("virtual_countries") or {}

        country_code = services_to_country_code.get(internal_data.requester)
        country_name = iso3166.get_country_name_from_code(
            country_code, extra=virtual_countries
        )
        service_has_alodp = has_service_alodp(
            internal_data.requester, country_code, services_marked_as_alodp
        )

        hash_id = generate_consent_id(
            internal_data.requester,
            internal_data.attributes,
            authorizations=authorizations,
            country_code=country_code,
            country_name=country_name,
            has_alodp=service_has_alodp,
        )

        api_url = config["api_url"]
        redirect_url = config["redirect_url"]
        signing_key = RSAKey(key=rsa_load(config["sign_key"]), use="sig", alg="RS256")

        if not enforce_consent:
            try:
                # Check if consent is already given
                logger.info("Querying the User Info Service to verify the consent")
                consent_attributes = verify_consent(api_url, hash_id)
                logger.info(
                    "Finished querying the User Info Service to verify the consent"
                )
            except ConnectionError as e:
                logger.error("User Info Service is unreachable: {}".format(str(e)))

                # Send an internal_data without any attributes
                internal_data.attributes = {}

                return self._end_consent(context, internal_data)

            # Previous confirmation was given
            if consent_attributes is not None:
                logger.info("Found active consent")
                internal_data.attributes = filter_items_exist(
                    internal_data.attributes,
                    consent_attributes
                )
                return self._end_consent(context, internal_data)

        # No previous consent, request consent by user
        context.state[STATE_KEY]["internal_resp"] = internal_data.to_dict()

        endpoint = "{base}/consent{endpoint}".format(
            base=self.base_url,
            endpoint=self.endpoint
        )
        requester = internal_data.requester
        requester_md = internal_data.metadata.get(requester, {})
        policy = requester_md.get("privacy_statement")
        display_name = requester_md.get('display_name')
        requester_name = [{'lang': 'en', 'text': display_name}]

        consent_args = {
            "attr": internal_data.attributes,
            "id": hash_id,
            "redirect_endpoint": endpoint,
            "requester": internal_data.requester,
            "requester_name": requester_name,
            "privacy_policy_url": policy,
            "authorizations": authorizations,
            "country_code": country_code,
            "country_name": country_name,
            "has_alodp": service_has_alodp,
            "has_agreed_to_tou": service_has_agreed_to_tou,
            "enforce_consent": enforce_consent,
        }
        if self.locked_attr:
            consent_args["locked_attrs"] = [self.locked_attr]
        if "requester_logo" in context.state[STATE_KEY]:
            consent_args["requester_logo"] = context.state[STATE_KEY]["requester_logo"]

        try:
            ticket = invoke_consent_registration(api_url, signing_key, consent_args)
        except (ConnectionError, UnexpectedResponseError) as e:
            logger.error("Confirmation request failed: {}".format(str(e)))
            # Send internal_data without any attributes
            internal_data.attributes = {}
            return self._end_consent(context, internal_data)

        consent_redirect = "%s/%s" % (redirect_url, ticket)
        logger.info(f"Sending user to the User Inform Service: {consent_redirect}")
        return Redirect(consent_redirect)

    def register_endpoints(self):
        """
        Register consent module endpoints

        :rtype: list[(srt, (satosa.context.Context) -> Any)]

        :return: A list of endpoints bound to a function
        """
        return [("^consent%s$" % self.endpoint, self._handle_consent_response)]


def filter_items_exist(items, keep):
    return {k: v for k, v in items.items() if k in keep}


def invoke_consent_registration(api_url, signing_key, consent_args):
    """
    Register a request at the User Info Service

    :type consent_args: dict
    :rtype: str

    :param consent_args: All necessary parameters for the confirmation request
    :return: Ticket received from the User Info Service
    """
    jws = JWS(json.dumps(consent_args), alg=signing_key.alg).sign_compact([signing_key])
    request = "{}/creq".format(api_url)
    res = requests.post(request, json={'jwt': jws})

    if res.status_code != 200:
        raise UnexpectedResponseError(
            "User Info Service error: %s %s" % (res.status_code, res.text)
        )

    return res.json().get('ticket')


def verify_consent(api_url, consent_id):
    """
    Connects to the User Info Service using the REST api and checks if the user has given consent

    :type consent_id: str
    :rtype: Optional[List[str]]

    :param consent_id: An id associated to the authenticated user, the calling requester and
    attributes to be sent.
    :return: list attributes given which have been approved by user consent
    """
    request = "{}/verify/{}".format(api_url, consent_id)
    res = requests.get(request)

    if res.status_code == 200:
        return json.loads(res.text)

    return None


def generate_consent_id(
    requester,
    attributes,
    authorizations=None,
    country_code=None,
    country_name=None,
    has_alodp=None,
):
    """
    Get an identifier for this mix of requester, user information and authorizations

    :type requester: str
    :type attributes: dict[str, str]
    :type authorizations: [str]

    :param requester: The calling requester
    :param attributes: a list containing all attributes to be sent
    :param authorizations: a list containing all authorizations to be sent
    :return: an id
    """

    attributes_list = list(attributes.keys())
    data = serialize_as_json(
        {
            "attributes": attributes_list,
            "authorizations": authorizations,
            "requester": requester,
            "country_code": country_code,
            "country_name": country_name,
            "has_alodp": has_alodp,
        },
        sort_keys=False,
        indent=None,
        default=None,
        separators=(',', ':'),
    )
    data_hashed = hash_sha512(data.encode("utf-8")).hexdigest()
    data_encoded = urlsafe_b64encode(data_hashed.encode("utf-8"))
    result = data_encoded.decode("utf-8")
    return result


def has_service_alodp(service, country_code, services_marked_as_alodp):
    has_alodp = (
        country_code in iso3166.countries_w_adequate_level_of_data_protection
        or service in services_marked_as_alodp
    )
    return has_alodp
