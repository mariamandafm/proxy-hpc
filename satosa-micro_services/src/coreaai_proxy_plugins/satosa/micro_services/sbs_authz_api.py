from logging import getLogger as get_logger
from typing import Mapping
from typing import Sequence
from urllib.parse import urlparse as _parse_url
from urllib.parse import parse_qsl as _parse_qsl
from urllib.parse import urlencode as _encode_qp

from pydantic import Field
from pydantic.dataclasses import dataclass

from requests import post as post_request
from requests.auth import HTTPBasicAuth

from toolz.itertoolz import groupby

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect

from coreaai_proxy_plugins.helpers.config import SecretStr
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper
from coreaai_proxy_plugins.helpers.xml import is_valid_xml_string


logger = ExtraLogger(get_logger(__name__))

API_REQUEST_TIMEOUT = 3
RESPONSE_STATUS_RESULT_AUTHORIZED = "authorized"
RESPONSE_STATUS_RESULT_UNAUTHORIZED = "unauthorized"
RESPONSE_STATUS_RESULT_INTERRUPT = "interrupt"
ACCEPTED_RESPONSE_STATUS_RESULTS = [
    RESPONSE_STATUS_RESULT_AUTHORIZED,
    RESPONSE_STATUS_RESULT_UNAUTHORIZED,
    RESPONSE_STATUS_RESULT_INTERRUPT,
]


class Config(TableConfig):
    api_to_internal_attributes: Mapping
    user_id_attribute: str
    user_email_attribute: str
    error_url: AnyHttpUrl
    continue_url_state_key: str
    api_url: AnyHttpUrl
    api_user: str
    api_password: SecretStr
    api_request_timeout: int = API_REQUEST_TIMEOUT
    additional_attributes: Mapping = Field(default_factory=dict)
    registration_authorities: list[str] = Field(default_factory=list)


class SBSAPIClientError(SATOSAError):
    """Generic error."""


@dataclass(frozen=True)
class ResultError(SBSAPIClientError):
    """Error response from SBS API"""

    message: str
    user_id_attribute: str
    user_email_attribute: str
    user_id: str
    user_email: str
    status_redirect_url: AnyHttpUrl


@dataclass(frozen=True)
class UnauthorizedUserError(ResultError):
    """Error raised when response status result is unauthorized."""


@dataclass(frozen=True)
class InterruptFlowError(ResultError):
    """Error raised when response status result is interrupt."""

    continue_url: AnyHttpUrl
    redirect_url: AnyHttpUrl


class SBSAPIClient(ResponseMicroService):
    """
    example configuration:

    ```
    module: satosa.micro_services.sbs_authz_api.SBSAPIClient
    name: SBSAPIClient
    config:
      - # configuration applies to any connection towards the specified requester from
        # an issuer as defined below. If the requester is empty the configuration
        # applies for any requester towards an issuer as defined below.
        # Optional; default is None
        requester: id-of-service

        # configuration applies to any connection from that issuer towards a requester
        # as defined above. If the issuer is empty the configuration applies for any
        # issuer towards a requester as defined above.
        # Optional; default is None
        issuer: id-of-provider

        # whether to skip processing for this pair of requester and issuer
        # Optional; default is False
        skip: false

        # The internal attribute of SATOSA from where we get the CUID of the user
        user_id_attribute: subject-id

        # The internal attribute of SATOSA from where we get the email of the user
        user_email_attribute: mail

        # The URL where we will redirect the user in case of an error from the SBS API
        error_url: https://...

        # The URL of the SBS API
        api_url:

        # The username used to authenticate at the SBS API
        api_user:

        # The passwored used to authenticate at the SBS API
        api_password:

        # Number of seconds before the HTTP request to the SBS API times out.
        # Default is 3
        api_request_timeout:

        # The additional attributes to send to SBS, for specified  registration
        # authorities. The attributes are mapped to a query param name.
        # Default is {}
        additional_attributes: {}

        # The registration authorities for which additional attributes will be sent to
        # SBS if the IdP is registered with them.
        # Default is []
        registration_authorities: []
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)
        table_configs: Sequence[Config] = [
            Config(
                registration_authorities=c.get("registration_authorities", []),
                additional_attributes=c.get("additional_attributes", {}),
                api_to_internal_attributes=c["api_to_internal_attributes"],
                user_id_attribute=c["user_id_attribute"],
                user_email_attribute=c["user_email_attribute"],
                error_url=c["error_url"],
                continue_url_state_key=c["continue_url_state_key"],
                api_url=c["api_url"],
                api_user=c["api_user"],
                api_password=c["api_password"],
                api_request_timeout=c.get("api_request_timeout", API_REQUEST_TIMEOUT),
                requester=c.get("requester"),
                issuer=c.get("issuer"),
                skip=c.get("skip"),
            )
            for c in config
        ]
        hierarchial_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchial_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        try:
            result = _process(context, data, config)
        except InterruptFlowError as e:
            logger.info(e)
            return Redirect(e.redirect_url)
        except UnauthorizedUserError as e:
            logger.info(e)
            return Redirect(e.status_redirect_url)
        except SBSAPIClientError as e:
            logger.warning(e)
            return Redirect(config.error_url)
        except Exception as e:
            logger.error(e)
            return Redirect(config.error_url)
        else:
            # otherwise we got a response to continue with the flow
            context, data = result

        return super().process(context, data)


def _process(context: Context, data: InternalData, config: Config):
    requester = data.requester
    issuer = data.auth_info.issuer
    user_id = next(iter(data.attributes.get(config.user_id_attribute) or []), None)
    user_email = next(iter(data.attributes.get(config.user_email_attribute) or []), None)
    registration_authority = (
        data.metadata.get(issuer, {}).get("registration_info", {}).get("registration_authority")
    )
    if not user_id:
        error_context = {
            "message": "Attribute value not usable as user_id",
            "user_id_attribute": config.user_id_attribute,
            "user_id": user_id,
        }
        raise SBSAPIClientError(error_context)

    if not user_email:
        error_context = {
            "message": "Attribute value not usable as user_email",
            "user_email_attribute": config.user_email_attribute,
            "user_email": user_email,
        }
        raise SBSAPIClientError(error_context)

    base_data = {
        "user_id": user_id,
        "user_email": user_email,
        "service_id": requester,
        "issuer_id": issuer,
    }
    additional_data = (
        {
            attr_qs: next(iter(data.attributes.get(attr, [])), None)
            for attr, attr_qs in config.additional_attributes.items()
        }
        if registration_authority in config.registration_authorities
        else {}
    )

    request_data = {
        **base_data,
        **additional_data,
    }
    try:
        response = post_request(
            config.api_url,
            auth=HTTPBasicAuth(config.api_user, config.api_password.get_secret_value()),
            json=request_data,
            timeout=config.api_request_timeout,
        )
        logger.debug({"message": "Request response data", "data": response.text})
    except Exception as e:
        error_context = {
            "message": "Request failed with error",
            "api_url": config.api_url,
            "request_data": request_data,
            "timeout": config.api_request_timeout,
            "error": str(e),
        }
        raise SBSAPIClientError(error_context) from e

    if response.status_code != 200:
        error_context = {
            "message": "Request returned with failure status code",
            "api_url": config.api_url,
            "request_data": request_data,
            "status_code": response.status_code,
            "reason": response.reason,
        }
        raise SBSAPIClientError(error_context)

    try:
        response_data = response.json()
    except Exception as e:
        error_context = {
            "message": "Response is not a JSON document",
            "api_url": config.api_url,
            "request_data": request_data,
            "content": response.text,
            "error": str(e),
        }
        raise SBSAPIClientError(error_context) from e

    status_result = response_data.get("status", {}).get("result")
    if not status_result:
        error_context = {
            "message": "Response does not contain a status result",
            "api_url": config.api_url,
            "request_data": request_data,
            "content": response.text,
            "status_result": status_result,
        }
        raise SBSAPIClientError(error_context)

    if status_result not in ACCEPTED_RESPONSE_STATUS_RESULTS:
        error_context = {
            "message": "Response contains invalid status result",
            "api_url": config.api_url,
            "request_data": request_data,
            "content": response.text,
            "status_result": status_result,
            "accepted_response_status_results": ACCEPTED_RESPONSE_STATUS_RESULTS,
        }
        raise SBSAPIClientError(error_context)

    if status_result in [
        RESPONSE_STATUS_RESULT_UNAUTHORIZED,
        RESPONSE_STATUS_RESULT_INTERRUPT,
    ]:
        status_redirect_url = response_data.get("status", {}).get("redirect_url")
        if not status_redirect_url:
            error_context = {
                "message": "Response does not contain a status redirect_url",
                "api_url": config.api_url,
                "request_data": request_data,
                "content": response.text,
                "status_result": status_result,
                "status_redirect_url": status_redirect_url,
            }
            raise SBSAPIClientError(error_context)

        if status_result == RESPONSE_STATUS_RESULT_UNAUTHORIZED:
            raise UnauthorizedUserError(
                message="User is unauthorized and will be redirected",
                user_id_attribute=config.user_id_attribute,
                user_id=user_id,
                user_email_attribute=config.user_email_attribute,
                user_email=user_email,
                status_redirect_url=status_redirect_url,
            )

        if status_result == RESPONSE_STATUS_RESULT_INTERRUPT:
            continue_url = context.state.get(config.continue_url_state_key)
            if not continue_url:
                error_context = {
                    "message": "State does not have a continue_url; cannot handle interrupt.",
                    "api_url": config.api_url,
                    "request_data": request_data,
                    "content": response.text,
                    "status_result": status_result,
                    "status_redirect_url": status_redirect_url,
                    "continue_url_state_key": config.continue_url_state_key,
                    "continue_url": continue_url,
                }
                raise SBSAPIClientError(error_context)

            redirect_url_obj = _parse_url(status_redirect_url)
            query_params = {
                **dict(_parse_qsl(redirect_url_obj.query)),
                "continue_url": continue_url,
            }
            qs_new = _encode_qp(query_params)
            redirect_url_obj_new = redirect_url_obj._replace(query=qs_new)
            redirect_url = redirect_url_obj_new.geturl()

            raise InterruptFlowError(
                message="Flow is interrupted and user will be redirected",
                user_id_attribute=config.user_id_attribute,
                user_id=user_id,
                user_email_attribute=config.user_email_attribute,
                user_email=user_email,
                status_redirect_url=status_redirect_url,
                continue_url=continue_url,
                redirect_url=redirect_url,
            )

    if status_result == RESPONSE_STATUS_RESULT_AUTHORIZED:
        response_attributes_unchecked = response_data.get("attributes", {})
        response_attributes_invalid = {}
        response_attributes_valid = {}
        for attr, values in response_attributes_unchecked.items():
            validity = groupby(is_valid_xml_string, values)
            response_attributes_valid[attr] = validity.get(True, [])
            response_attributes_invalid[attr] = validity.get(False, [])

        if any(response_attributes_invalid.values()):
            report_warn = {
                "message": "Invalid attribute values found",
                "response_attributes_invalid": response_attributes_invalid,
            }
            logger.warning(report_warn)

        response_attributes_translated = {
            int_attr: values
            for api_attr, values in response_attributes_valid.items()
            for int_attr in [config.api_to_internal_attributes.get(api_attr)]
            if int_attr
        }
        attributes_enhanced = {
            **data.attributes,
            **response_attributes_translated,
        }

        report: Mapping = {
            "message": "User is authorized with attributes",
            "response_attributes_valid": response_attributes_valid.keys(),
            "response_attributes_translated": response_attributes_translated.keys(),
            "attributes_enhanced": attributes_enhanced.keys(),
        }
        report_dbg = {
            **report,
            "response_attributes_valid": response_attributes_valid,
            "response_attributes_translated": response_attributes_translated,
            "attributes_enhanced": attributes_enhanced,
        }
        logger.info(report)
        logger.debug(report_dbg)

        data.attributes = attributes_enhanced

    return context, data
