from base64 import urlsafe_b64decode
from copy import deepcopy as _clone
from json import dumps as _serialize_to_json
from json import loads as load_as_json
from logging import getLogger as get_logger
from lzma import compress as compress_w_lzma
from lzma import decompress as decompress_w_lzma

from typing import Mapping, Optional
from typing import Sequence

from cryptography.fernet import Fernet

from satosa.internal import InternalData
from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.micro_services.base import RequestMicroService
from satosa.micro_services.base import ResponseMicroService

from requests import get as get_request
from requests import post as post_request
from requests import put as put_request

from coreaai_proxy_plugins.helpers.config import SecretStr
from coreaai_proxy_plugins.helpers.config import AnyHttpUrl
from coreaai_proxy_plugins.helpers.config import TableConfig
from coreaai_proxy_plugins.helpers.config import resolve_config_wrapper
from coreaai_proxy_plugins.helpers.config import get_default_conf_from_hierarchy
from coreaai_proxy_plugins.helpers.config import restructure_table_config_to_hierarchical_config

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))

API_REQUEST_TIMEOUT = 2


class Error(SATOSAError):
    """Generic error for this micro-service"""


class Config(TableConfig):
    continue_path: str
    continue_url_state_key: str
    state_key: str
    encryption_key: SecretStr
    additional_state_keys: list[str]
    api_base_url: AnyHttpUrl
    api_key: SecretStr
    api_req_timeout: int = API_REQUEST_TIMEOUT


class SessionStoreReqAPI(RequestMicroService):
    """
    Store and retrieve a user session using an API service.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.session_store_req.SessionStoreReqAPI
    name: Store and retrieve a user session using an API service.
    config:
      - continue_path: session/continue
        state_key: session_req
        encryption_key: "a URL-safe base64-encoded 32-byte key"
        additional_state_keys:
          - MetaInfoService
          - authorizations
        api_base_url: https://sessionstore.example.com
        api_key: very_secret_api_access_key
        api_req_timeout: 2
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    continue_path=c["continue_path"],
                    continue_url_state_key=c["continue_url_state_key"],
                    state_key=c["state_key"],
                    encryption_key=c["encryption_key"],
                    additional_state_keys=c["additional_state_keys"],
                    api_base_url=c["api_base_url"],
                    api_key=c["api_key"],
                    api_req_timeout=c.get("api_req_timeout", API_REQUEST_TIMEOUT),
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise Error("Invalid configuration") from e
        if not table_configs:
            raise Error("Invalid configuration")
        hierarchial_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchial_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        session_data = collect_data_from_request_session(
            context, config.additional_state_keys, config.state_key
        )
        payload = get_payload_from_session_data(
            session_data, config.encryption_key.get_secret_value()
        )
        session_id = post_session_payload_to_api(
            payload,
            api_base_url=config.api_base_url,
            api_key=config.api_key.get_secret_value(),
            api_timeout=config.api_req_timeout,
        )
        log_context = {
            "message": "Stored request session data",
            "session_data": session_data,
            "payload": payload,
            "session_id": session_id,
        }
        logger.debug(log_context)

        context.state[config.state_key] = session_id
        return super().process(context, data)

    def _handle_continue_session(self, context):
        config = get_default_conf_from_hierarchy(self.config)
        _, session_store_id = context.path.split(f"{config.continue_path}/", maxsplit=1)
        payload, expires_at = get_session_payload_from_api(
            session_store_id,
            api_base_url=config.api_base_url,
            api_key=config.api_key.get_secret_value(),
            api_timeout=config.api_req_timeout,
        )
        # XXX FIXME check expires_at
        session_data = get_session_data_from_payload(
            payload, config.encryption_key.get_secret_value()
        )

        # extract info
        idp_used_to_register = session_data["memorized_idp"]
        state = session_data["state"]
        target_backend = session_data["target_backend"]
        target_frontend = session_data["target_frontend"]
        target_micro_service = session_data["target_micro_service"]

        log_context = {
            "message": "Restored stored session",
            "session_data": session_data,
        }
        logger.debug(log_context)

        # set the values
        context.decorate(Context.KEY_TARGET_ENTITYID, idp_used_to_register)
        context.state.data = {
            **context.state.state_dict,
            **state,
        }
        context.target_backend = target_backend
        context.target_frontend = target_frontend
        context.target_micro_service = target_micro_service
        return self.process(context, InternalData())

    def register_endpoints(self):
        config = get_default_conf_from_hierarchy(self.config)
        url_map = [(f"^{config.continue_path}/.*$", self._handle_continue_session)]
        return url_map


class SessionStoreResAPI(ResponseMicroService):
    """
    Store and retrieve a user session using an API service.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.session_store_req.SessionStoreResAPI
    name: Store and retrieve a user session using an API service.
    config:
      - continue_path: continue
        state_key: session_req
        encryption_key: "a URL-safe base64-encoded 32-byte key"
        continue_url_state_key: cont_url
        api_base_url: https://sessionstore.example.com
        api_key: very_secret_api_access_key
        api_req_timeout: 2
    ```
    """

    def __init__(self, config: Sequence[Mapping], *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    continue_path=c["continue_path"],
                    continue_url_state_key=c["continue_url_state_key"],
                    state_key=c["state_key"],
                    encryption_key=c["encryption_key"],
                    additional_state_keys=c["additional_state_keys"],
                    api_base_url=c["api_base_url"],
                    api_key=c["api_key"],
                    api_req_timeout=c.get("api_req_timeout", API_REQUEST_TIMEOUT),
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise Error("Invalid configuration") from e
        if not table_configs:
            raise Error("Invalid configuration")
        hierarchial_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )
        self.config = hierarchial_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        session_store_id = context.state[config.state_key]
        request_session_payload, expires_at = get_session_payload_from_api(
            session_store_id,
            api_base_url=config.api_base_url,
            api_key=config.api_key.get_secret_value(),
            api_timeout=config.api_req_timeout,
        )
        # XXX FIXME check expires_at
        request_session_data = get_session_data_from_payload(
            request_session_payload, config.encryption_key.get_secret_value()
        )

        log_context = {
            "message": "Retrieved request session data",
            "session_data": request_session_data,
            "payload": request_session_payload,
        }
        logger.debug(log_context)

        response_session_data = collect_data_from_response_session(
            context, [], config.state_key
        )
        session_data = {**request_session_data, **response_session_data}
        session_payload = get_payload_from_session_data(
            session_data, config.encryption_key.get_secret_value()
        )
        session_id, expires_at = put_session_payload_to_api(
            session_store_id,
            session_payload,
            api_base_url=config.api_base_url,
            api_key=config.api_key.get_secret_value(),
            api_timeout=config.api_req_timeout,
        )
        # XXX FIXME check expires_at
        continue_url = f"{self.base_url}/{config.continue_path}/{session_id}"

        log_context = {
            "message": (
                "generated continue_url based on request and response session data"
            ),
            "continue_url_state_key": config.continue_url_state_key,
            "continue_url": continue_url,
            "session_data": session_data,
            "payload": session_payload,
        }
        logger.debug(log_context)

        # clean state and store new continue URL
        context.state.pop(config.state_key, None)
        context.state[config.continue_url_state_key] = continue_url
        return super().process(context, data)


class SessionStoreCompat_pre_api(RequestMicroService):
    """
    module: coreaai_proxy_plugins.satosa.micro_services.session_store_req.SessionStoreCompat_pre_api
    name: SessionStoreCompat
    description: Session-store compatibility before introducing the session-store api
    config:
      continue_path: continue
      encryption_key: "a URL-safe base64-encoded 32-byte key"
    """

    def __init__(self, config: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.continue_path = config["continue_path"]
        self.encryption_key = config["encryption_key"]

    def _handle_registration_response(self, context):
        internal_data = InternalData()
        _, payload = context.path.split(f"{self.continue_path}/", maxsplit=1)

        def v7_11(ser_state):
            # decode data
            ser_state = ser_state.encode("utf-8")
            ser_state = urlsafe_b64decode(ser_state)
            ser_state = decompress_w_lzma(ser_state)
            ser_state = ser_state.decode("utf-8")
            data = load_as_json(ser_state)

            # extract info
            idp_used_to_register = data["memorized_idp"]
            request_data = data["request_data"]
            request_state = request_data["state"]
            request_target_backend = request_data["target_backend"]
            request_target_frontend = request_data["target_frontend"]
            request_target_micro_service = request_data["target_micro_service"]

            # set the values
            context.decorate(Context.KEY_TARGET_ENTITYID, idp_used_to_register)
            context.state.data = request_state
            context.target_backend = request_target_backend
            context.target_frontend = request_target_frontend
            context.target_micro_service = request_target_micro_service

        def v7_12(payload):
            session_data = get_session_data_from_payload(payload, self.encryption_key)

            # extract info
            idp_used_to_register = session_data["memorized_idp"]
            state = session_data["state"]
            target_backend = session_data["target_backend"]
            target_frontend = session_data["target_frontend"]
            target_micro_service = session_data["target_micro_service"]

            log_context = {
                "message": "Restored stored session",
                "session_data": session_data,
            }
            logger.debug(log_context)

            # set the values
            context.decorate(Context.KEY_TARGET_ENTITYID, idp_used_to_register)
            context.state.data = {
                **context.state.state_dict,
                **state,
            }
            context.target_backend = target_backend
            context.target_frontend = target_frontend
            context.target_micro_service = target_micro_service

        try:
            v7_11(ser_state=payload)
        except Exception as e_v7_11:
            pass
        else:
            return self.process(context, internal_data)

        try:
            v7_12(payload=payload)
        except Exception as e_v7_12:
            pass
        else:
            return self.process(context, internal_data)

        error_context = {
            "message": "Invalid continue-URL payload",
            "payload": payload,
            "continue_path": self.continue_path,
        }
        raise Error(error_context)

    def register_endpoints(self):
        url_map = [(f"^{self.continue_path}/.*$", self._handle_registration_response)]
        return url_map


class StoreAndReprocessAuthnReq(RequestMicroService):
    """
    module: coreaai_proxy_plugins.satosa.micro_services.session_store_req.StoreAndReprocessAuthnReq
    name: Store and reprocess the request session
    config:
      continue_path: continue
      state_key: session_req
      encryption_key: "a URL-safe base64-encoded 32-byte key"
      additional_state_keys:
        - MetaInfoService
        - authorizations
    """

    def __init__(self, config: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state_key = config["state_key"]
        self.continue_path = config["continue_path"]
        self.encryption_key = config["encryption_key"]
        self.additional_state_keys = config.get("additional_state_keys") or []

    @logging_wrapper(logger)
    def process(self, context: Context, internal_data: InternalData):
        request_session = collect_data_from_request_session(
            context, self.additional_state_keys, self.state_key
        )

        log_context = {
            "message": "Stored request session",
            "request_session": request_session,
        }
        logger.debug(log_context)

        context.state[self.state_key] = request_session
        return super().process(context, internal_data)

    def _handle_registration_response(self, context):
        internal_data = InternalData()
        _, payload = context.path.split(f"{self.continue_path}/", maxsplit=2)
        session_data = get_session_data_from_payload(payload, self.encryption_key)

        # extract info
        idp_used_to_register = session_data["memorized_idp"]
        state = session_data["state"]
        target_backend = session_data["target_backend"]
        target_frontend = session_data["target_frontend"]
        target_micro_service = session_data["target_micro_service"]

        log_context = {
            "message": "Restored stored session",
            "session_data": session_data,
        }
        logger.debug(log_context)

        # set the values
        context.decorate(Context.KEY_TARGET_ENTITYID, idp_used_to_register)
        context.state.data = {
            **context.state.state_dict,
            **state,
        }
        context.target_backend = target_backend
        context.target_frontend = target_frontend
        context.target_micro_service = target_micro_service
        return self.process(context, internal_data)

    def register_endpoints(self):
        url_map = [(f"^{self.continue_path}/.*$", self._handle_registration_response)]
        return url_map


class StoreAndReprocessReqRes(ResponseMicroService):
    """
    module: coreaai_proxy_plugins.satosa.micro_services.session_store_req.StoreAndReprocessReqRes
    name: Store and reprocess the request session
    config:
      continue_path: continue
      state_key: session_req
      continue_url_state_key: continue_url
      encryption_key: "a URL-safe base64-encoded 32-byte key"
    """

    def __init__(self, config: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.continue_path = config["continue_path"]
        self.state_key = config["state_key"]
        self.continue_url_state_key = config["continue_url_state_key"]
        self.encryption_key = config["encryption_key"]

    @logging_wrapper(logger)
    def process(self, context: Context, internal_data: InternalData):
        request_data = context.state.get(self.state_key, {})
        response_data = collect_data_from_response_session(context, [], self.state_key)

        # pack info
        session_data = {**request_data, **response_data}
        payload = get_payload_from_session_data(session_data, self.encryption_key)

        base_url = self.base_url
        continue_url = f"{base_url}/{self.continue_path}/{payload}"

        log_context = {
            "message": "generated continue_url based on request and response state",
            "continue_url_state_key": self.continue_url_state_key,
            "continue_url": continue_url,
            "session_data": session_data,
        }
        logger.debug(log_context)

        # clean state and store new continue URL
        context.state.pop(self.state_key, None)
        context.state[self.continue_url_state_key] = continue_url
        return super().process(context, internal_data)


def serialize_to_json(data):
    s = _serialize_to_json(
        data,
        sort_keys=False,
        indent=None,
        default=None,
        separators=(",", ":"),
    )
    return s


def collect_data_from_request_session(context, additional_state_keys, state_key=None):
    context_target_micro_service = _clone(context.target_micro_service)
    context_target_frontend = _clone(context.target_frontend)
    context_target_backend = _clone(context.target_backend)

    state_items_to_keep = {
        # standard
        "SESSION_ID",
        "SATOSA_BASE",
        "ROUTER",
        # dynamic
        context.target_micro_service,
        context.target_backend,  # ie, 'saml2sp'
        context.target_frontend,  # ie, 'Saml2IDP'
    }.union(k for k in additional_state_keys)
    context_state = {
        key: _clone(value)
        for key, value in context.state.state_dict.items()
        if key is not None and key in state_items_to_keep
        # exclude previous state stored by this plugin
        if key != state_key
    }

    request_session = {
        "target_micro_service": context_target_micro_service,
        "target_frontend": context_target_frontend,
        "target_backend": context_target_backend,
        "state": context_state,
        # later more fields are added:
        # "memorized_idp": "<entityID>",
    }
    return request_session


def collect_data_from_response_session(context, additional_state_keys, state_key=None):
    memorized_idp = context.get_decoration(Context.KEY_MEMORIZED_IDP)
    response_session = {
        "memorized_idp": memorized_idp,
    }
    return response_session


def get_payload_from_session_data(session_data, encryption_key):
    ser_state = serialize_to_json(session_data)
    ser_state = ser_state.encode("utf-8")
    ser_state = compress_w_lzma(ser_state)
    ser_state = Fernet(encryption_key).encrypt(ser_state)
    payload = ser_state.decode("utf-8")
    return payload


def get_session_data_from_payload(payload, encryption_key):
    deser_state = payload.encode("utf-8")
    deser_state = Fernet(encryption_key).decrypt(deser_state)
    deser_state = decompress_w_lzma(deser_state)
    deser_state = deser_state.decode("utf-8")
    data = load_as_json(deser_state)
    return data


def get_session_payload_from_api(
    session_id, api_base_url, api_key, api_timeout
) -> tuple[str, float]:
    api_url = f"{api_base_url}/session_store/{session_id}"
    try:
        response = get_request(
            api_url,
            headers={
                "Authorization": f"Bearer {api_key}",
            },
            timeout=api_timeout,
        )
    except Exception as e:
        error_context = {
            "message": "Request failed with error",
            "api_url": api_url,
            "api_timeout": api_timeout,
        }
        raise Error(error_context) from e

    if response.status_code != 200:
        error_context = {
            "message": "Response returned with failure status code",
            "api_url": api_url,
            "status_code": response.status_code,
            "reason": response.reason,
        }
        raise Error(error_context)

    try:
        response_data = response.json()
    except Exception as e:
        error_context = {
            "message": "Response is not a JSON document",
            "api_url": api_url,
            "content": response.text,
        }
        raise Error(error_context) from e

    payload = response_data.get("session")
    expires_at = response_data.get("expires_at")
    if not payload:
        error_context = {
            "message": "Response did not contain session",
            "api_url": api_url,
            "response_data": response_data,
        }
        raise Error(error_context)
    if not expires_at:
        error_context = {
            "message": "Response did not contain expiration",
            "api_url": api_url,
            "response_data": response_data,
        }
        raise Error(error_context)

    return payload, expires_at


def post_session_payload_to_api(
    session_data: str, api_base_url: str, api_key: str, api_timeout: Optional[float]
) -> str:
    api_url = f"{api_base_url}/session_store/"
    request_data = {
        "session": session_data,
    }
    try:
        response = post_request(
            api_url,
            headers={
                "Authorization": f"Bearer {api_key}",
            },
            data=request_data,
            timeout=API_REQUEST_TIMEOUT,
        )
    except Exception as e:
        error_context = {
            "message": "Request failed with error",
            "api_url": api_url,
            "api_timeout": api_timeout,
            "request_data": request_data,
        }
        raise Error(error_context) from e

    if response.status_code != 200:
        error_context = {
            "message": "Response returned with failure status code",
            "api_url": api_url,
            "request_data": request_data,
            "status_code": response.status_code,
            "reason": response.reason,
        }
        raise Error(error_context)

    try:
        response_data = response.json()
    except Exception as e:
        error_context = {
            "message": "Response is not a JSON document",
            "api_url": api_url,
            "request_data": request_data,
            "content": response.text,
        }
        raise Error(error_context) from e

    session_store_id = response_data.get("session_id")
    if not session_store_id:
        error_context = {
            "message": "Response did not contain a session_id",
            "api_url": api_url,
            "request_data": request_data,
            "response_data": response_data,
        }
        raise Error(error_context)

    return session_store_id


def put_session_payload_to_api(
    session_id, session_data, api_base_url, api_key, api_timeout
) -> tuple[str, str]:
    api_url = f"{api_base_url}/session_store/{session_id}"
    request_data = {
        "session": session_data,
    }
    try:
        response = put_request(
            api_url,
            headers={
                "Authorization": f"Bearer {api_key}",
            },
            data=request_data,
            timeout=API_REQUEST_TIMEOUT,
        )
    except Exception as e:
        error_context = {
            "message": "Request failed with error",
            "api_url": api_url,
            "api_timeout": api_timeout,
            "request_data": request_data,
        }
        raise Error(error_context) from e

    if response.status_code != 200:
        error_context = {
            "message": "Response returned with failure status code",
            "api_url": api_url,
            "request_data": request_data,
            "status_code": response.status_code,
            "reason": response.reason,
        }
        raise Error(error_context)

    try:
        response_data = response.json()
    except Exception as e:
        error_context = {
            "message": "Response is not a JSON document",
            "api_url": api_url,
            "request_data": request_data,
            "content": response.text,
        }
        raise Error(error_context) from e

    session_store_id = response_data.get("session_id")
    expires_at = response_data.get("expires_at")
    if not session_store_id:
        error_context = {
            "message": "Response did not contain a session_id",
            "api_url": api_url,
            "request_data": request_data,
            "response_data": response_data,
        }
        raise Error(error_context)
    if not expires_at:
        error_context = {
            "message": "Response did not contain expiration",
            "api_url": api_url,
            "request_data": request_data,
            "response_data": response_data,
        }
        raise Error(error_context)

    return session_store_id, expires_at
