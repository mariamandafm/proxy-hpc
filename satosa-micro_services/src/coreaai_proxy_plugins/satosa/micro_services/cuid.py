"""
SATOSA microservice that queries the CUID app to retrieve a CUID for the user
"""

import logging
import requests
import re
from validators import url as is_valid_url

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from coreaai_proxy_plugins.helpers.config import parse_config
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))

API_REQUEST_TIMEOUT = 3


class CUIDError(SATOSAError):
    """Generic error."""


class CUIDClient(ResponseMicroService):
    """
    example configuration:
    ```
    module: coreaai_proxy_plugins.satosa.micro_services.cuid
    name: CUID
    config:
      issuer:
        requester:
          access_token: random-string
          api_endpoint: https://localhost/cuid/
          api_req_timeout: 5
          iuid_attribute: vopersonexternalid
          cuid_attribute: subject_id
          scope: example.org
          disabled: false
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for issuer in config:
            for requester in config[issuer]:
                try:
                    access_token = config[issuer][requester].get("access_token")
                    api_endpoint = config[issuer][requester].get("api_endpoint")
                    api_req_timeout = config[issuer][requester].get(
                        "api_req_timeout", API_REQUEST_TIMEOUT
                    )
                    iuid_attribute = config[issuer][requester].get("iuid_attribute")
                    cuid_attribute = config[issuer][requester].get("cuid_attribute")
                    scope = config[issuer][requester].get("scope")
                    disabled = config[issuer][requester].get("disabled")
                except Exception as err:
                    raise CUIDError(err)

                if disabled:
                    continue

                validators = {
                    "access_token is set and it is a string": (
                        type(access_token) is str and access_token
                    ),
                    "api_endpoint is set and it is a string": (
                        type(api_endpoint) is str and bool(
                            is_valid_url(api_endpoint, simple_host=True)
                        )
                    ),
                    "api_req_timeout is a number": type(api_req_timeout) is int,
                    "iuid_attribute is set and it is a string": (
                        type(iuid_attribute) is str and iuid_attribute
                    ),
                    "cuid_attribute is set and it is a string": (
                        type(cuid_attribute) is str and cuid_attribute
                    ),
                    "scope is set and it is a string": (type(scope) is str and scope),
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
                        "config": config,
                        "validators": validators,
                        "issuer": issuer,
                        "requester": requester,
                    }
                    raise CUIDError(log_data)

        self.config = config

    @logging_wrapper(logger)
    def process(self, context, internal_data):
        requester = internal_data.requester
        issuer = internal_data.auth_info.issuer
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
            return super().process(context, internal_data)

        access_token = config.get("access_token")
        api_endpoint = config.get("api_endpoint")
        api_req_timeout = config.get("api_req_timeout", API_REQUEST_TIMEOUT)
        iuid_attribute = config.get("iuid_attribute")
        cuid_attribute = config.get("cuid_attribute")
        scope = config.get("scope")

        if iuid_attribute not in internal_data["attributes"]:
            log_data = {
                "message": "The IUID attribute was empty",
                "iuid_attribute": iuid_attribute,
            }
            raise CUIDError(log_data)

        iuids = internal_data["attributes"].get(iuid_attribute)
        if not iuids:
            log_data = {
                "message": "The IUID attribute value was empty",
                "iuid_attribute": iuid_attribute,
                "iuids": iuids,
            }
            raise CUIDError(log_data)

        request_data = {
            "json": iuids,
            "timeout": api_req_timeout,
        }
        try:
            response = requests.post(
                api_endpoint,
                params={"access_token": access_token},
                **request_data,
            )
        except Exception as e:
            log_data = {
                "message": "Failed to query the CUID API",
                "error": e,
            }
            raise CUIDError(log_data)

        if response.status_code == 409:
            logger.warning("Multiple CUIDs found for IUIDs: {}".format(iuids))
            log_data = {
                "message": "Multiple CUIDs found",
                "iuids": iuids,
            }
            raise CUIDError(log_data)

        if response.status_code not in [200, 201]:
            log_data = {
                "message": "Unexpected HTTP status code",
                "status_code": response.status_code,
                "response": response.text,
            }
            raise CUIDError(log_data)

        cuid = response.json().get("cuid")
        if response.status_code == 201:
            logger.debug(f"New CUID was minted: {cuid}")

        if scope:
            cuid = f"{cuid}@{scope}"
        internal_data["attributes"][cuid_attribute] = [cuid]
        return super().process(context, internal_data)
