from json import dumps as _serialize_as_json
from typing import Mapping
from typing import NewType
from typing import Optional
from typing import TypeVar
from typing import Sequence
from typing import NoReturn

from pydantic import AnyUrl as _AnyUrl
from pydantic import AnyHttpUrl as _AnyHttpUrl
from pydantic import BaseModel
from pydantic import HttpUrl as _HttpUrl
from pydantic import SecretStr as _SecretStr
from pydantic import validator
from pydantic.json import pydantic_encoder as _pydantic_json_encoder
from satosa.context import Context
from satosa.internal import InternalData

from toolz.itertoolz import groupby as _groupby


class ConfigError(Exception):
    """Generic error raised when manipulating the configuration"""


class AnyUrl(_AnyUrl):
    pass


class AnyHttpUrl(_AnyHttpUrl):
    pass


class HttpUrl(_HttpUrl):
    pass


class SecretStr(_SecretStr):
    pass


Requester = NewType("Requester", str)
Issuer = NewType("Issuer", str)


class TableConfig(BaseModel):
    requester: Optional[Requester] = Requester("")
    issuer: Optional[Issuer] = Issuer("")
    skip: Optional[bool] = False

    @validator('requester', always=True, pre=True)
    def coerce_requester(cls, v):
        return Requester("") if v in [None, ""] else v

    @validator('issuer', always=True, pre=True)
    def coerce_issuer(cls, v):
        return Issuer("") if v in [None, ""] else v

    @validator('skip', always=True, pre=True)
    def coerce_skip(cls, v):
        return False if v is None else v

    class Config:
        frozen = True
        allow_mutation = False
        arbitrary_types_allowed = True


TConfig = TypeVar("TConfig", bound=TableConfig)
HierarchicalConfig = Mapping[Requester, Mapping[Issuer, TConfig]]


def get_default_conf_from_hierarchy(config: HierarchicalConfig[TConfig]) -> TConfig:
    default = config[Requester("")][Issuer("")]
    return default


def restructure_table_config_to_hierarchical_config(
    table_configs: Sequence[TConfig],
) -> HierarchicalConfig[TConfig]:
    """
    Restructure config objects with requester-issuer pairs to a hierarchy.

    The hierarchy is formed as dictionaries within dictionaries where the top level
    represents the requesters and the lower level represents the issuers. The values are
    the config objects themselves.

    The function assumes config objects have .requester and .issuer fields/properties.
    """

    def raise_error(error_context) -> NoReturn:
        raise ConfigError(error_context)

    hierarchical_config = {
        requester: {
            issuer: iss_cfgs[0]
            if len(iss_cfgs) == 1
            else raise_error(
                {
                    "message": "Multiple configurations for same requester-issuer pair",
                    "requester": requester,
                    "issuer": issuer,
                    "configs": iss_cfgs,
                }
            )
            for issuer, iss_cfgs in _groupby(lambda x: x.issuer, req_cfgs).items()
        }
        for requester, req_cfgs in _groupby(
            lambda x: x.requester, table_configs
        ).items()
    }

    return hierarchical_config


def get_config_from_hierarchy(
    config_hierarchy: HierarchicalConfig[TConfig], requester: Requester, issuer: Issuer
) -> TConfig:
    """
    Resolve and return the proper configuration object from the given hierarchy.

    The resolution prioritizes requester configurations specialized by issuer
    configurations. Given a requester and an issuer, the preference order is:
      - requester-issuer: configuration for specific requester and specific issuer
      - requester-unspecified: configuration for specific requester and any issuer
      - unspecified-issuer: configuration for any requester and specific issuer
      - unspecified-unspecified: configuration for any issuer and any requester
    """

    config_req_unspec = config_hierarchy.get(Requester("")) or {}
    config_req_unspec_iss_unspec = config_req_unspec.get(Issuer(""))
    if not config_req_unspec_iss_unspec:
        error_context = {
            "messsage": "No configuration defined for the fallback case",
            "requester": "<unspecified>",
            "issuer": "<unspecified>",
        }
        raise ConfigError(error_context)

    config_req = config_hierarchy.get(requester, config_req_unspec)
    config_req_iss_unspec = config_req.get(Issuer("")) or config_req_unspec_iss_unspec
    config_req_iss = config_req.get(issuer, config_req_iss_unspec)
    return config_req_iss

def resolve_config(hconfig: HierarchicalConfig[TConfig], internal_data: InternalData) -> TConfig:
    context :Context
    requester = Requester(internal_data.requester)
    issuer = internal_data.auth_info.issuer or Issuer("")
    config = get_config_from_hierarchy(hconfig, requester, issuer)
    return config

def resolve_config_wrapper(logger):
    def decorator(plugin_process):
        def process_resolve_config_wrapper(self, context, internal_data):
            config = resolve_config(self.config, internal_data)
            logger.debug(
                serialize_as_json(
                    {
                        "message": "resolved configuration",
                        "config": config,
                    }
                )
            )
            result = plugin_process(self, context, internal_data, config)
            return result

        return process_resolve_config_wrapper

    return decorator


def parse_config(config, issuer, requester):
    issuer_config = get_key_or_defaults(config, issuer)
    requester_config = get_key_or_defaults(config, requester)
    req_iss_config = get_key_or_defaults(requester_config or {}, issuer)
    iss_req_config = get_key_or_defaults(issuer_config or {}, requester)
    config_by = {
        "by-issuer": issuer_config,
        "by-requester": requester_config,
        "by-req-iss": req_iss_config,
        "by-iss-req": iss_req_config,
    }
    return config_by


def get_key_or_defaults(data, key):
    value_key = data.get(key)
    value_empty = data.get("")
    value_default = data.get("default")
    value = (
        value_key
        if value_key is not None
        else value_empty
        if value_empty is not None
        else value_default
    )
    return value


def serialize_as_json(data):
    value = _serialize_as_json(data, default=_pydantic_json_encoder)
    return value
