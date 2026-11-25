import base64
import json
import logging
from collections import defaultdict

from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.config import parse_config
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class ActiveAttributeSelectionError(SATOSAError):
    pass


class ActiveAttributeSelection(ResponseMicroService):
    """
    Allow the user to select which attributes should be active.

    An external service is used to render the attributes and allow the user to interact
    with them. The response from that service is used to replace the appropriate
    attributes of the user that will be sent as part of the authentication response.

    Example configuration:

    ```
    module: satosa.micro_services.active_attribute_selection.ActiveAttributeSelection
    name: ActiveAttributeSelection
    config:
      endpoint: "handler"
      redirect_url: "https://domain.tld/path/to/external/service/endpoint"
      selection_attributes:
        # - the empty string key is used to denote the default settings (legagy)
        # - the "default" string key is used to denote the default settings
        # - the non-empty (and not "default") string key is used to match an entity-id
        # - the entity-id can be an issuer or a requester
        # - the issuer has precedence over the requester
        default:
          default:
            # If there is no match for the issuer id or the requester id then use this
            # configuration
            - attribute-name
          https://sp.example.com:
            # If there is no match for the issuer id but there is a match for the
            # requester id then use this configuration
            - attribute-name
          https://idp.example.com
            # If there is no match for the requester id but there is a match for the
            # issuer id then use this configuration
            - attribute-name
        https://idp.example.com:
          default:
            # If there is a match for the issuer id but there is not match for the
            # requester id then use this configuration
            - attribute-name
          https://sp.example.com:
            # If there is a match for the issuer id and then the requester id then use
            # this configuration
            - attribute-name
        https://sp.example.com:
          default:
            # If there is a match for the requester id but there is not match for the
            # issuer id then use this configuration
            - attribute-name
          https://idp.example.com:
            # If there is a match for the requester id and then the issuer id then use
            # this configuration
            - attribute-name
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        endpoint = config.get("endpoint")
        redirect_url = config.get("redirect_url")
        selection_attributes = defaultdict(
            lambda: config.get("selection_attributes", {}).get("", {}),
            config.get("selection_attributes", {}),
        )

        selection_attributes_is_required_to_be_a_non_empty_dict_of_str_to_dict = (
            isinstance(selection_attributes, dict)
            and len(selection_attributes)
            and all(
                isinstance(entity_id, str)
                and isinstance(inner_conf, dict)
                for entity_id, inner_conf in selection_attributes.items()
            )
        )
        selection_attributes_inner_conf_is_required_to_be_a_non_empty_dict_of_str_to_list = (
            selection_attributes_is_required_to_be_a_non_empty_dict_of_str_to_dict
            and all(
                len(inner_conf)
                and all(
                    isinstance(entity_id, str)
                    and isinstance(attributes, list)
                    for entity_id, attributes in inner_conf.items()
                )
                for entity_id, inner_conf in selection_attributes.items()
            )
        )
        selection_attributes_inner_conf_list_is_required_to_be_a_list_of_str = (
            selection_attributes_inner_conf_is_required_to_be_a_non_empty_dict_of_str_to_list
            and all(
                all(
                    isinstance(attribute, str)
                    for entity_id, attributes in inner_conf.items()
                    for attribute in attributes
                )
                for entity_id, inner_conf in selection_attributes.items()
            )
        )
        validators = {
            "redirect_url is required to be a string": type(redirect_url) is str,
            "endpoint is required to be a string": type(endpoint) is str,
            "selection_attributes is required to be a non-empty dict of str to dict": (
                selection_attributes_is_required_to_be_a_non_empty_dict_of_str_to_dict
            ),
            "selection_attributes inner conf is required to be a non-empty dict of str to list": (
                selection_attributes_inner_conf_is_required_to_be_a_non_empty_dict_of_str_to_list
            ),
            "selection_attributes inner conf list is required to be a list of str": (
                selection_attributes_inner_conf_list_is_required_to_be_a_list_of_str
            ),
        }
        if not all(validators.values()):
            error_context = {
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
            logger.error(error_context)
            raise ActiveAttributeSelectionError(error_context)

        self.endpoint = endpoint
        self.redirect_url = redirect_url
        self.selection_attributes = selection_attributes
        logger.info("Active Attribute Selection flow is active")

    @property
    def response_endpoint(self):
        urlpath = "{name}/{endpoint}/".format(name=self.name, endpoint=self.endpoint)
        return urlpath

    def register_endpoints(self):
        """
        Register aas module endpoints
        :rtype: list[(srt, (satosa.context.Context) -> Any)]
        :return: A list of endpoints bound to a function
        """
        url_map = [("^{}.*$".format(self.response_endpoint), self._handle_response)]
        return url_map

    @logging_wrapper(logger)
    def process(self, context, internal_data):
        store_internal_data(context.state, self.name, internal_data.to_dict())

        requester = internal_data.requester
        issuer = internal_data.auth_info.issuer
        config = parse_config(self.selection_attributes, issuer, requester)

        mdstore = internal_data.get("metadata", {})
        requester_name = mdstore.get(requester, {}).get("display_name") or requester

        selection_attributes = (
            config["by-iss-req"]
            or config["by-req-iss"]
            or {}
        )
        logger.info("Initialized with configuration: {}".format(selection_attributes))

        selections = gather_selections(internal_data.attributes, selection_attributes)

        # if no attributes have values then continue
        if all(
            svalues is None or svalues == [] for sname, svalues in selections.items()
        ):
            logger.warning("No attributes have values")
            return super().process(context, internal_data)

        payload = {
            "attributes": selections,
            "requester": requester,
            "requester_name": requester_name,
        }
        serialized = serialize_payload(payload)

        redirect_url = "{location}/{data}".format(
            location=self.redirect_url, data=serialized
        )

        return Redirect(redirect_url)

    def _handle_response(self, context):
        """
        Endpoint for handling the response from the Active Attribute Selection service.

        :type context: satosa.context.Context
        :rtype: satosa.response.Response
        :param context: response context
        :return: response
        """

        logger.bind("session_id", context.state.session_id)
        logger.info("Continue processing")

        internal_data = restore_internal_data(context.state, self.name)
        requester = internal_data.requester
        issuer = internal_data.auth_info.issuer
        config = parse_config(self.selection_attributes, issuer, requester)

        selection_attributes = (
            config["by-iss-req"]
            or config["by-req-iss"]
            or {}
        )

        logger.debug("Re-initialized with configuration: {}".format(selection_attributes))

        selections = gather_selections(internal_data.attributes, selection_attributes)

        serialized = context._path.replace(self.response_endpoint, "")
        payload = deserialize_payload(serialized)
        validate_payload(selections, payload)

        logger.debug("Validated payload from Active Attribute Selection Service: {}".format(payload))

        selected_attributes = {
            attr_name: payload["attributes"].get(attr_name, [])
            for attr_name in selection_attributes
        }
        internal_data.attributes.update(selected_attributes)

        logger.debug("Returning attributes: {}".format(str(internal_data.attributes)))
        logger.info("Finished processing")

        return super().process(context, internal_data)


def validate_payload(selections, payload):
    """
    Validate the payload we received from the request.

    The response data must
    - payload is a dictionary object
    - have a field named "attributes"
    - have all keys matched with the given choices/selections
    - have all values matched with values of the given choices/selections
    """
    payload_has_type_dict = isinstance(payload, dict)
    payload_has_valid_fields = payload_has_type_dict and all(
        field in payload.keys() for field in ["attributes"]
    )
    payload_attribute_names_match_selections = payload_has_valid_fields and all(
        attribute_name in selections.keys()
        for attribute_name in payload["attributes"].keys()
    )
    payload_attribute_values_match_selections = (
        payload_attribute_names_match_selections
        and all(
            pvalue in selections[pname]
            for pname, pvalues in payload["attributes"].items()
            for pvalue in pvalues
        )
    )

    validators = {
        "payload has valid fields": payload_has_valid_fields,
        "payload attribute names match selections": payload_attribute_names_match_selections,
        "payload attribute values match selections": payload_attribute_values_match_selections,
    }
    if not all(validators.values()):
        error_context = {
            "message": "Invalid payload received.",
            "validators": validators,
            "selections": selections,
            "payload": payload,
        }
        raise ActiveAttributeSelectionError(error_context)

    return True


def gather_selections(attributes, selections):
    selections = {
        sname: values
        for sname in selections
        for values in [attributes.get(sname)]
        if values
    }
    return selections


def store_internal_data(state, key, value):
    state[key] = {"internal_data": value}


def restore_internal_data(state, key):
    state = state.pop(key, {})
    response_data = state.get("internal_data", {})
    data = InternalData.from_dict(response_data)
    return data


def serialize_payload(payload):
    serialized = json.dumps(payload)
    encoded = serialized.encode("utf-8")
    b64encoded = base64.urlsafe_b64encode(encoded)
    encoded = b64encoded.decode("utf-8")
    return encoded


def deserialize_payload(serialized_payload):
    try:
        b64decoded = base64.urlsafe_b64decode(serialized_payload)
        decoded = b64decoded.decode("utf-8")
        unserialized = json.loads(decoded)
    except Exception as e:
        error_context = {
            "message": "Cannot decode data to expected format",
            "payload": serialized_payload,
            "exception": str(e),
        }
        logger.error(error_context)
        raise ActiveAttributeSelectionError(error_context)
    else:
        return unserialized
