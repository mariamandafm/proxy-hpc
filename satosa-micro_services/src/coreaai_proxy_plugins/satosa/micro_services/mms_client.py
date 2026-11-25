"""
SATOSA microservice that uses an identifier asserted by
the home organization SAML IdP as a key to search a DB
for records and then consume attributes from
the record and assert them to the receiving SP.
"""

import json
import logging
from base64 import b64encode

import requests

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class MMSClientError(SATOSAError):
    """Generic error."""


class MMSClient(ResponseMicroService):
    """lookup a person record in REST SERVER and obtain attributes."""

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            # XXX Should we validate the type of each configuration option?
            # XXX ie, what will happen if api_user is a list?
            self.api_uri = config["api_uri"]
            self.api_user = config["api_user"]
            self.api_secret = config["api_secret"]
            self.attribute_as_uid = config["attribute_as_uid"]
            self.skip_services = config.get("skip_services") or []
            self.attribute_mappings = config.get("attribute_mappings") or {}
        except KeyError as err:
            raise MMSClientError("{} is not configured".format(err))

    @logging_wrapper(logger)
    def process(self, context, data):
        return_values = []
        requester = data.requester

        if requester in self.skip_services:
            return super().process(context, data)

        try:
            user_pass = b64encode(
                bytearray("{}:{}".format(self.api_user, self.api_secret), "utf-8")
            ).decode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Basic {auth_data}".format(auth_data=user_pass),
            }

            # XXX What should happen if this attribute is missing?
            user_to_query = data.attributes[self.attribute_as_uid]

            # XXX What should happen if this does not hold?
            # XXX Can we use user_to_query without unpacking?
            # XXX What is user_to_query if not a list of items?
            # if this is a list (eg. id_generator microservice puts SPUC into a one-item list) we need to unpack it first.
            if isinstance(user_to_query, list) and (len(user_to_query) > 0):
                user_to_query = user_to_query[0]

            api_uri_complete = "{0}?uid={1}&service_entity_id={2}".format(
                self.api_uri, user_to_query, requester
            )
            logger.debug("Requesting URI:{}".format(api_uri_complete))

            response = requests.get(api_uri_complete, headers=headers)
            if response.status_code != 200:
                logger.error("Non-200 return error: {}".format(response.status_code))
                # XXX Should an error be raised here?
            else:
                logger.debug("Response:\n{}".format(response.text))
                # XXX What should happen if the response is not json?
                json_data = json.loads(response.text)

                if json_data is not None:
                    dct = {}

                    # FIXME These mappings are now hardcoded. They should be
                    # FIXME configurable in the same way that we do for the
                    # FIXME attribute_store micro_service
                    #
                    # XXX What should happen if the response is not valid?
                    # XXX ie, it doesn't have the structure we expect
                    # XXX ie, an attribute is not included
                    for mms_attr, internal_attr in self.attribute_mappings.items():
                        if mms_attr in json_data:
                            dct[internal_attr] = json_data[mms_attr]

                    return_values.append(dct)

        except Exception as err:
            # XXX Should the flow continue if this micro-service fails?
            logger.error("Caught exception: {}".format(err))
            return super().process(context, data)

        # XXX What should happen if we do not get any values?
        # merging return values with incoming
        if return_values:
            for retval in return_values:
                for k in retval:
                    v = retval[k]
                    if isinstance(v, str):
                        v = [v]
                    if k in data.attributes:
                        data.attributes[k] = data.attributes[k] + v
                    else:
                        data.attributes[k] = v

        return super().process(context, data)
