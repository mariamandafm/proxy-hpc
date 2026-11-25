import binascii
import functools
import hashlib
import importlib
import inspect
import json
import logging
from base64 import b64decode, b64encode
from contextlib import contextmanager
from copy import deepcopy
from operator import iconcat
from pydantic import BaseModel, HttpUrl, ValidationError, SecretStr
 
from typing import Mapping, List, Optional

import bcrypt
import requests
from idpyoidc.util import qualified_name
from requests.exceptions import Timeout
import satosa.logging_util as lu
from idpyoidc.message.oauth2 import (
    AuthorizationErrorResponse,
    TokenErrorResponse,
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
)
from idpyoidc.server import Server, exception
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.client_authn import ClientAuthnMethod
from idpyoidc.server.endpoint import fragment_encoding
from idpyoidc.server.exception import ClientAuthenticationError
from idpyoidc.server.oauth2 import authorization
from idpyoidc.server.oauth2.add_on.pkce import CC_METHOD
from idpyoidc.server.scopes import SCOPE2CLAIMS
from idpyoidc.server.session.claims import available_claims
from idpyoidc.server.session.grant import ExchangeGrant, Grant
from idpyoidc.server.session.info import ClientSessionInfo, UserSessionInfo
from idpyoidc.server.session.token import AccessToken as OIDCAccessToken
from idpyoidc.server.token.id_token import IDToken as OIDCIDToken
from idpyoidc.time_util import utc_time_sans_frac

# TODO: Should remove dependence to old frontend module
from satosa.exception import SATOSAConfigurationError
from satosa.frontends.base import FrontendModule
from satosa.frontends.openid_connect import combine_claim_values
from satosa.internal import InternalData
from satosa.response import BadRequest, Created, Redirect, Response, Unauthorized
from satosa_oidc_frontend.helpers.client_credentials_filter_policies import (
    validate_client_credentials_filter_policy,
)
from satosa_oidc_frontend.helpers.resource_indicators_policies import (
    validate_authorization_resource_indicators_policy,
    validate_token_resource_indicators_policy,
)
from satosa_oidc_frontend.helpers.token_exchange_policies import (
    validate_token_exchange_policy,
)
from satosa_oidc_frontend.helpers.token_revocation_policies import (
    validate_token_revocation_policy,
)
from satosa_oidc_frontend.libraries.letty_api import LettyClientsAPI
from satosa_oidc_frontend.models import (
    AccessToken,
    AuthorizationCode,
    Base,
    Client,
    ClientSession,
    GrantSession,
    IDToken,
    RefreshToken,
    User,
    UserSession,
)
from satosa_oidc_frontend.types import ClientSource
from satosa_oidc_frontend.utils import (
    check_current_head,
    check_request_method,
    create_db,
    get_token_from_header,
    session_manager_dump,
    token_class_to_str,
)
from sqlalchemy import and_, create_engine, false, func, or_
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

try:
    from satosa.exception import SATOSAMissingStateError
except:  # noqa: E722
    from satosa.exception import SATOSAError

    # XXX TODO introduce this error upstream
    class SATOSAMissingStateError(SATOSAError):
        """
        SATOSA Missing State error.

        This exception should be raised when SATOSA receives a request as part of
        an authentication flow and while the session state cookie is expected for
        that step, it is not included in the request
        """

        def __init__(self, error):
            self.error = error


logger = logging.getLogger(__name__)
engine = None
KEY_REQUESTER_METADATA = "requester_metadata"


def init_engine(db_uri):
    global engine
    if not engine:
        engine = create_engine(db_uri, echo=False)
        # If no table exists then we generate them and stamp the db
        create_db(engine, Base)
        # Check if migrations are needed.
        if db_uri != "sqlite:///:memory:" and not check_current_head(engine):
            logger.error(
                "Migrations are needed please apply migrations by running: "
                "`SATOSA_OIDC_FRONTEND_DB_URI={db_uri} satosa-oidc-frontend-db "
                "migrate`"
            )


def modsplit(s):
    c = s.split(".")
    if len(c) < 2:
        raise SATOSAConfigurationError("Syntax error: {s}")
    return ".".join(c[:-1]), c[-1]


def importer(name):
    c1, c2 = modsplit(name)
    module = importlib.import_module(c1)
    return getattr(module, c2)


def import_class(cls_path, fun, kwargs):
    try:
        cls = importer(cls_path)
    except AttributeError as e:
        raise SATOSAConfigurationError(*e.args)

    if not inspect.isclass(cls):
        raise SATOSAConfigurationError(f"'{cls_path}' is not a class")
    cls = cls(**kwargs)

    if fun:
        if not hasattr(cls, fun):
            raise SATOSAConfigurationError(
                f"The provided class '{cls_path}' has no attribute '{fun}'"
            )

        if not callable(cls.fun):
            raise SATOSAConfigurationError(
                f"The provided function '{fun}' for class '{cls_path}' is not "
                "callable"
            )

        ret = cls.fun
    else:
        if not callable(cls):
            raise SATOSAConfigurationError(
                f"The provided class '{cls_path}' is not callable"
            )
        ret = cls

    return ret


def update(d, u):
    for k, v in u.items():
        if isinstance(v, dict):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


class ProviderConfig(dict):
    default_params = {
        "response_types_supported": ["code"],
        "client_authn_method_mapping": None,
        "client_authn_method": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
        ],
        "scopes_to_claims": SCOPE2CLAIMS,
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["pairwise"],
        "claim_types_supported": ["normal"],
        "extra_scopes": {},
        "user_db": {},
        "client_secret_expiration_time": 432000,
        "access_token_claims": [],
        "jwt_access_token": False,
        "id_token_lifetime": 300,
        "id_token_default_claims": [],
        "id_token_enable_claims_per_client": False,
        "userinfo_enable_claims_per_client": False,
        "access_token_lifetime": 3600,
        "at_enable_claims_per_client": False,
        "refresh_token_lifetime": 86400,
        "code_lifetime": 300,
        "jwks_uri": "jwks",
        "authorization_path": "authorization",
        "token_path": "token",
        "userinfo_path": "userinfo",
        "enable_registration_endpoint": False,
        "registration_path": "register",
        "registration_authn": ["bearer_header", "bearer_body"],
        "enable_introspection_endpoint": False,
        "enable_revocation_endpoint": False,
        "introspection_path": "introspect",
        "token_revocation_path": "revoke",
        "token_revocation_authn": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "bearer_header",
            "bearer_body",
        ],
        "enable_introspection_claims_per_client": False,
        "pkce": True,
        "claims_supported": [],
        "sub_func": {"public": {"function": lambda id, *args, **kwargs: id}},
        "token_session_encryption_password": None,
        "token_encryption_password": "",
        "token_exchange_policy": {"": {"function": validate_token_exchange_policy}},
        "token_exchange_subject_token_types_supported": [
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token",
        ],
        "token_exchange_requested_token_types_supported": [
            "urn:ietf:params:oauth:token-type:access_token",
            "urn:ietf:params:oauth:token-type:refresh_token",
            "urn:ietf:params:oauth:token-type:id_token",
        ],
        "token_revocation_policy": {"": {"function": validate_token_revocation_policy}},
        "client_credentials_policy": {
            "": {"function": validate_client_credentials_filter_policy}
        },
        "enable_resource_indicators": False,
        "enable_audience_policies": False,
        "audience_policies": None,
        "schemes_denylist": None,
        "default_requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "deny_unknown_scopes": True,
        "id_token_add_claims_by_scope": False,
        "activate_regex_scopes": False,
        "allowed_scopes_regex": [],
        "revoke_refresh_on_issue": False,
        "db_uri": None,
        "enforce_audience_restriction": False,
    }

    default_config = {
        # Verify the SSL cert used by the server
        "verify_ssl": True,
        "token_handler_args": {
            "jwks_def": {
                # These keys are used for encrypting the access code, the
                # refresh token and the access token(when it's not a JWT),
                # I don't think these should be configurable.
                # Should these keys be stored somewhere?
                "read_only": True,
                "private_path": None,
                "key_defs": [
                    {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "code"},
                    {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "refresh"},
                    {"type": "oct", "bytes": 24, "use": ["enc"], "kid": "token"},
                ],
            },
            "jwks_file": None,
        },
        "template_handler": None,
        "endpoint": {
            # The names of the endpoints are unused from idpyoidc
        },
        "add_on": {},
        "claims_interface": {"class": "idpyoidc.server.session.claims.ClaimsInterface"},
        "session_params": {},
    }

    def __init__(self, claims=None, **kwargs):
        # Deepcopy the default config and params so it can be used again, e.g.
        # for running 2 instances of the frontend.
        self.update(deepcopy(self.default_config))
        self.params = dict(deepcopy(self.default_params), **kwargs)

        if "db_uri" in self.params and self.params["db_uri"] is not None:
            self.db_uri = self.params["db_uri"]
            init_engine(self.params["db_uri"])

        self.configure()

        if "attribute_auth" in kwargs:
            AttributeAuth.CHECK_FOR_ATTRIBUTES = True
            AttributeAuth.ATTRIBUTES = kwargs["attribute_auth"]

    def configure(self):
        self.configure_issuer()
        self.configure_session_params()
        self.configure_scopes()
        self.configure_capabilities()
        self.configure_client_authn()

        self.configure_token_handler_args()
        self.configure_userinfo()
        self.configure_endpoints()
        self.configure_jwks()

        self.configure_pkce()
        self.configure_authz()
        self.configure_cookie_handler()

    def configure_issuer(self):
        self["issuer"] = self.params.get("issuer")

    def configure_session_params(self):
        self.configure_sub_func()

    def configure_sub_func(self):
        self["session_params"]["sub_func"] = self.params["sub_func"]
        if not self.params["token_session_encryption_password"]:
            raise SATOSAConfigurationError(
                "A value for `token_session_encryption_password` must be provided in "
                "the configuration"
            )
        self["session_params"]["encrypter"] = {
            "kwargs": {
                "key": hashlib.sha256(
                    self.params["token_session_encryption_password"].encode("utf-8")
                ).digest(),
                "salt": "",
            },
        }

    def configure_endpoints(self):
        self.configure_provider_info()
        self.configure_authorization()
        if self.params["enable_registration_endpoint"]:
            self.configure_registration()
        # If flow not implicit
        if any("code" in typ for typ in self.params["response_types_supported"]):
            self.configure_token()
            if self.params["userinfo_path"]:
                self.configure_userinfo_endpoint()
        if self.params["enable_introspection_endpoint"]:
            self.configure_introspection()
        if self.params["enable_revocation_endpoint"]:
            self.configure_revocation()

    def configure_capabilities(self):
        self["preference"] = {
            "response_types_supported": self.params["response_types_supported"],
            "subject_types_supported": self.params["subject_types_supported"],
            "claim_types_supported": self.params["claim_types_supported"],
            "client_authn_method": self.params["client_authn_method"],
            "claims_supported": self.params["claims_supported"],
            "deny_unknown_scopes": self.params["deny_unknown_scopes"],
            "grant_types_supported": self.params["grant_types_supported"],
        }
        if "scopes_supported" in self.params:
            self["preference"]["scopes_supported"] = self.params["scopes_supported"]

    def configure_scopes(self):
        if self.params["scopes_to_claims"] is not None:
            if "openid" not in self.params["scopes_to_claims"]:
                self.params["scopes_to_claims"]["openid"] = ["sub"]
        if "scopes_supported" in self.params:
            self["scopes_supported"] = self.params["scopes_supported"]
        self["scopes_to_claims"] = self.params["scopes_to_claims"]
        if self.params["activate_regex_scopes"]:
            self["scopes_handler"] = {
                "class": "satosa_oidc_frontend.helpers.scopes.GenericScopes",
                "kwargs": {
                    "scopes_to_claims": self.params["scopes_to_claims"],
                    "allowed_scopes_regex": self.params["allowed_scopes_regex"],
                },
            }

    def configure_client_authn(self):
        if self.params["client_authn_method_mapping"] is not None:
            self["client_authn_methods"] = self.params["client_authn_method_mapping"]

    def configure_userinfo(self):
        self["userinfo"] = {
            "class": "idpyoidc.server.user_info.UserInfo",
            "kwargs": {},
        }

    def configure_token_handler_args(self):
        self.configure_access_token()
        self.configure_refresh_token()
        self.configure_id_token()
        self.configure_code()

    def configure_access_token(self):
        if self.params["jwt_access_token"]:
            self["token_handler_args"]["token"] = {
                "class": "idpyoidc.server.token.jwt_token.JWTToken",
                "kwargs": {
                    "add_claims": self.params["access_token_claims"],
                    "add_claims_by_scope": True,
                    "enable_claims_per_client": self.params[
                        "at_enable_claims_per_client"
                    ],
                    "lifetime": self.params["access_token_lifetime"],
                },
            }
        else:
            # Defaults to idpyoidc.server.token_handler.DefaultToken
            self["token_handler_args"]["token"] = {
                "kwargs": {
                    "lifetime": self.params["access_token_lifetime"],
                    "crypt_conf": {
                        "kwargs": {
                            "key": hashlib.sha256(
                                self.params["token_encryption_password"].encode("utf-8")
                            ).digest()
                        },
                    },
                }
            }

    def configure_code(self):
        self["token_handler_args"]["code"] = {
            "kwargs": {
                "lifetime": self.params["code_lifetime"],
                "crypt_conf": {
                    "kwargs": {
                        "key": hashlib.sha256(
                            self.params["token_encryption_password"].encode("utf-8")
                        ).digest()
                    },
                },
            }
        }

    def configure_refresh_token(self):
        self["token_handler_args"]["refresh"] = {
            "kwargs": {
                "lifetime": self.params["refresh_token_lifetime"],
                "crypt_conf": {
                    "kwargs": {
                        "key": hashlib.sha256(
                            self.params["token_encryption_password"].encode("utf-8")
                        ).digest()
                    },
                },
            }
        }

    def configure_id_token(self):
        self["token_handler_args"]["id_token"] = {
            "class": "idpyoidc.server.token.id_token.IDToken",
            "kwargs": {
                "base_claims": {
                    c: None for c in self.params["id_token_default_claims"]
                },
                "enable_claims_per_client": self.params[
                    "id_token_enable_claims_per_client"
                ],
                "lifetime": self.params["id_token_lifetime"],
                "add_claims_by_scope": self.params["id_token_add_claims_by_scope"],
            },
        }

    def configure_provider_info(self):
        self["endpoint"]["provider_config"] = {
            "path": ".well-known/openid-configuration",
            "class": "idpyoidc.server.oidc.provider_config.ProviderConfiguration",
        }

    def configure_authorization(self):
        self["endpoint"]["authorization"] = {
            "path": self.params["authorization_path"],
            "class": "idpyoidc.server.oidc.authorization.Authorization",
            "kwargs": {
                "response_types_supported": self.params["response_types_supported"],
                "response_modes_supported": self.params["response_modes_supported"],
                "grant_types_supported": self.params["grant_types_supported"],
                "claim_types_supported": self.params["claim_types_supported"],
            },
        }
        if self.params["schemes_denylist"]:
            self["endpoint"]["authorization"]["kwargs"]["schemes_denylist"] = (
                self.params["schemes_denylist"]
            )

        if self.params["enable_resource_indicators"]:
            self["endpoint"]["authorization"]["kwargs"]["enable_resource_indicators"] = True  
            self["endpoint"]["authorization"]["kwargs"]["resource_indicators"] = {
                "policy": {
                    "function": validate_authorization_resource_indicators_policy,
                }
            }
        if self.params["enable_audience_policies"]:
            self["endpoint"]["authorization"]["kwargs"]["enable_audience_policies"] = True  
            self["endpoint"]["authorization"]["kwargs"]["audience_policies"] = self.params["audience_policies"]

    def configure_registration(self):
        self["endpoint"]["registration"] = {
            "path": self.params["registration_path"],
            "class": "idpyoidc.server.oidc.registration.Registration",
            "kwargs": {
                "client_authn_method": self.params["registration_authn"],
                "client_secret_expiration_time": self.params[
                    "client_secret_expiration_time"
                ],
            },
        }

    def configure_token(self):
        grant_types_helpers = {
            "authorization_code": {
                "class": "idpyoidc.server.oidc.token.AccessTokenHelper"
            },
            "refresh_token": {"class": "idpyoidc.server.oidc.token.RefreshTokenHelper"},
            "urn:ietf:params:oauth:grant-type:token-exchange": {
                "class": "idpyoidc.server.oidc.token.TokenExchangeHelper",
                "kwargs": {
                    "subject_token_types_supported": self.params[
                        "token_exchange_subject_token_types_supported"
                    ],
                    "requested_token_types_supported": self.params[
                        "token_exchange_requested_token_types_supported"
                    ],
                    "default_requested_token_type": self.params[
                        "default_requested_token_type"
                    ],
                    "policy": self.params["token_exchange_policy"],
                },
            },
            "client_credentials": {
                "class": "idpyoidc.server.oauth2.token.ClientCredentials",
                "kwargs": {
                    "policy": self.params["client_credentials_policy"],
                },
            },
        }

        self["endpoint"]["token"] = {
            "path": self.params["token_path"],
            "class": "idpyoidc.server.oidc.token.Token",
            "kwargs": {
                "client_authn_method": self.params["client_authn_method"],
                "grant_types_supported": self.params["grant_types_supported"],
                "grant_types_helpers": grant_types_helpers,
                "revoke_refresh_on_issue": self.params["revoke_refresh_on_issue"],
            },
        }
        if self.params["refresh_token_lifetime"]:
            self["endpoint"]["token"]["kwargs"]["allow_refresh"] = True
        if self.params["enable_resource_indicators"]:
            self["endpoint"]["token"]["kwargs"]["enable_resource_indicators"] = True
            self["endpoint"]["token"]["kwargs"]["resource_indicators"] = {
                "policy": {
                    "function": validate_token_resource_indicators_policy
                }
           }
        if self.params["enable_audience_policies"]:
            self["endpoint"]["token"]["kwargs"]["enable_audience_policies"] = True
            self["endpoint"]["token"]["kwargs"]["audience_policies"] = self.params["audience_policies"]

    def configure_userinfo_endpoint(self):
        self["endpoint"]["userinfo"] = {
            "path": self.params["userinfo_path"],
            "class": "idpyoidc.server.oidc.userinfo.UserInfo",
            "kwargs": {
                "claim_types_supported": self.params["claim_types_supported"],
                "enable_claims_per_client": self.params[
                    "userinfo_enable_claims_per_client"
                ],
                "client_authn_method": ["bearer_header", "bearer_body"],
            },
        }

    def configure_introspection(self):
        self["endpoint"]["introspection"] = {
            "path": self.params["introspection_path"],
            "class": "idpyoidc.server.oauth2.introspection.Introspection",
            "kwargs": {
                "client_authn_method": self.params["client_authn_method"],
                "enable_claims_per_client": self.params[
                    "enable_introspection_claims_per_client"
                ],
                "enforce_audience_restriction": self.params[
                    "enforce_audience_restriction"
                ],
            },
        }
        if self.params["enable_audience_policies"]:
            self["endpoint"]["introspection"]["kwargs"]["enable_audience_policies"] = True
            self["endpoint"]["introspection"]["kwargs"]["audience_policies"] = self.params["audience_policies"]
           

    def configure_revocation(self):
        self["endpoint"]["token_revocation"] = {
            "path": self.params["token_revocation_path"],
            "class": "idpyoidc.server.oauth2.token_revocation.TokenRevocation",
            "kwargs": {
                "policy": self.params["token_revocation_policy"],
                "client_authn_method": self.params["token_revocation_authn"],
            },
        }
        if "revocation_supported_token_types" in self.params:
            self["endpoint"]["token_revocation"]["kwargs"]["token_types_supported"] = (
                self.params["revocation_supported_token_types"]
            )

    def configure_jwks(self):
        self["key_conf"] = {
            "uri_path": self.params["jwks_uri"],
            "private_path": self.params.get("jwks_private_path"),
            "public_path": self.params.get("jwks_public_path"),
            "key_defs": self.params.get(
                "jwks",
                [
                    # For id-token signing.
                    {"type": "RSA", "use": ["sig"]},
                    # JWT access token defaults to alg=ES256.
                    {"type": "EC", "crv": "P-256", "use": ["sig"]},
                ],
            ),
            "read_only": self.params.get("jwks_read_only", False),
        }

    def configure_pkce(self):
        if self.params["pkce"]:
            pkce_conf = self.params["pkce"]
            essential = False
            methods = CC_METHOD
            if isinstance(pkce_conf, dict):
                essential = pkce_conf.get("essential", essential)
                methods = pkce_conf.get("code_challenge_methods", methods)
            self["add_on"]["pkce"] = {
                "function": "idpyoidc.server.oauth2.add_on.pkce.add_support",
                "kwargs": {"essential": essential, "code_challenge_methods": methods},
            }

    def configure_authz(self):
        if not self.params["claims_supported"]:
            return

        claim_restrictions = {c: None for c in self.params["claims_supported"]}
        claims = {
            "id_token": claim_restrictions,
            "userinfo": claim_restrictions,
        }
        if self.params["enable_introspection_claims_per_client"]:
            claims["introspection"] = claim_restrictions
        if self.params["at_enable_claims_per_client"]:
            claims["token"] = claim_restrictions
        auth_code_rules = {
            "expires_in": self.params["code_lifetime"],
            "supports_minting": [
                "access_token",
                "id_token",
            ],
            "max_usage": 1,
        }
        if "refresh_token" in self.params["grant_types_supported"]:
            auth_code_rules["supports_minting"].append("refresh_token")

        self["authz"] = {
            "class": "idpyoidc.server.authz.AuthzHandling",
            "kwargs": {
                "grant_config": {
                    "usage_rules": {
                        "authorization_code": auth_code_rules,
                        "access_token": {
                            "expires_in": self.params["access_token_lifetime"],
                            "supports_minting": [
                                "access_token",
                                "refresh_token",
                                "id_token",
                            ],
                        },
                        "refresh_token": {
                            "expires_in": self.params["refresh_token_lifetime"],
                            "supports_minting": [
                                "access_token",
                                "refresh_token",
                                "id_token",
                            ],
                        },
                    },
                    "claims": claims,
                }
            },
        }

    def configure_cookie_handler(self):
        self["cookie_handler"] = {
            "class": "idpyoidc.server.cookie_handler.CookieHandler",
            "kwargs": {
                "name": {
                    "session": "oidc_op",
                    "register": "oidc_op_rp",
                    "session_management": "sman",
                }
            },
        }


class OpenIDConnectFrontend(FrontendModule):
    """
    An OpenID Connect frontend module
    """

    def __init__(
        self, auth_req_callback_func, internal_attributes, conf, base_url, name
    ):
        super().__init__(auth_req_callback_func, internal_attributes, base_url, name)

        self.config = conf
        self.import_hooks()
        self.configure_endpoints()
        self.server = Server(self.provider_config)
        self.endpoint_context = self.server.context

        self.init_database(conf)
        self.init_client_source()

        if "db_uri" in self.config:
            user_db = UserInfoDB()
        else:
            user_db = {}
        self.endpoint_context.userinfo.db = user_db
        self.user_db = self.endpoint_context.userinfo.db

        self.endpoint_context.cdb = self.client_db

    def log_request(
        self,
        context,
        endpoint="",
        code=None,
        access_token=None,
        refresh_token=None,
        session_id=None,
    ):
        if session_id is None:
            if code:
                token = code
            elif access_token:
                token = access_token
            elif refresh_token:
                token = refresh_token
            else:
                logger.error("No token provided")
                return

            try:
                session = (
                    self.endpoint_context.session_manager.get_session_info_by_token(
                        token
                    )
                )
                session_id = session["branch_id"]
            except KeyError:
                # We should never end up here
                logger.error(f"{endpoint} endpoint request has no branch_id")
                return
            except Exception as e:
                logger.error(
                    f"Couldn't get the session from the token, error: {str(e)}"
                )
                return

        msg = "{} endpoint request with branch_id={}".format(endpoint, session_id)
        satosa_session_id = lu.get_session_id(context.state)
        logline = lu.LOG_FMT.format(
            id=satosa_session_id,
            message=msg,
        )
        logger.info(logline)

    def init_database(self, conf):
        if "db_uri" in conf and conf["db_uri"] is not None:
            self.session_maker = sessionmaker(bind=engine)
            self.session_db = SessionDB(self.endpoint_context.session_manager)
        else:
            self.session_maker = None
            self.session_db = SessionDict()

    def init_client_source(self):
        if client_source_path := self.config.get("client_db_handler_class_path"):
            logger.debug("Using client source: %s", client_source_path)
            client_source_kwargs = self.config.get("client_db_handler_class_kwargs", {})
            self.client_db = importer(client_source_path)(**client_source_kwargs)
        else:
            logger.debug("Using client source: Empty dict")
            self.client_db = {}

        if self.config.get("client_db_enable_import") and self.config.get(
            "client_json_path"
        ):
            self.import_clients()

    def import_hooks(self):
        """
        Imports a list of hooks in the form of:
        hooks:
            - class: SomeClass
            - class: SomeClass2
              function: foo
            - class: SomeClass3
              kwargs:
                a: 1
                b: 2
            - class: SomeClass4
              function: foo
              kwargs:
                arg: 1

        If the hook is a class then kwargs are used to initialize the class and
        the provided function is called when the hook is run. If no function is
        provided then the class is called.

        """
        for param in ["introspection_post_process_hooks", "userinfo_post_process_hooks"]:
            hooks = self.config.get(param, [])
            if not isinstance(hooks, list):
                raise SATOSAConfigurationError(f"{param} must be a list")

            param_hooks = []
            for hook in hooks:
                cls = hook.get("class")
                if cls is None:
                    raise SATOSAConfigurationError(f"No class provided for '{param}'")
                fun = hook.get("function")
                kwargs = hook.get("kwargs", {})
                try:
                    param_hooks.append(import_class(cls, fun, kwargs))
                except ValidationError as e:
                    raise SATOSAConfigurationError(f"Error in configuration '{e}'")

            setattr(self, param, param_hooks)

    def configure_endpoints(self):
        attributes = self.internal_attributes["attributes"].values()
        claims_supported = [
            attribute_map["openid"][0]
            for attribute_map in attributes
            if "openid" in attribute_map
        ]

        issuer = self.config.get("issuer") or f"{self.base_url}/{self.name}"
        self.config["issuer"] = issuer

        self.provider_config = ProviderConfig(
            claims_supported=claims_supported, **self.config
        )

        provider = self.config.get("provider") or {}
        self.config["provider"] = provider
        self.provider_config = update(self.provider_config, self.config["provider"])

    def import_clients(self):
        with open(self.config["client_json_path"]) as f:
            clients = json.loads(f.read())
        for client, client_info in clients.items():
            if (
                self.config.get("overwrite_clients_in_db", True)
                or client not in self.client_db
            ):
                if (
                    self.config.get("client_db_enable_secret_hashing_on_import")
                    and client_info.get("client_secret") is not None
                ):
                    client_info["client_secret"] = self.hash_client_secret(
                        client_info["client_secret"]
                    )
                self.client_db[client] = client_info

    def hash_client_secret(self, plaintext_secret):
        return bcrypt.hashpw(
            plaintext_secret.encode(),
            bcrypt.gensalt(),
        ).decode()

    def _unpack_session_key(self, session_id):
        sids = self.endpoint_context.session_manager.unpack_session_key(session_id)
        client_id = grant_id = None
        if len(sids) == 1:
            user_id = sids[0]
        elif len(sids) == 2:
            user_id, client_id = sids
        elif len(sids) == 3:
            user_id, client_id, grant_id = sids
        else:
            raise ValueError("Unknown sid format")
        return user_id, client_id, grant_id

    def store_sessions(self, sessions=None):
        if not sessions:
            _sessions = self.endpoint_context.session_manager.db
            sessions = {}
            for key, session in _sessions.items():
                if isinstance(session, Grant):
                    comp_sid = self.endpoint_context.session_manager._compatible_sid(
                        key
                    )
                    # When loading the session we also add the grant under the
                    # compatible sid key for backwards compatibility, we dump it now
                    # since this info is stored in the grant
                    if comp_sid == key:
                        continue
                    for token in session.issued_token:
                        if token.max_usage_reached():
                            token.revoke()
                sessions[key] = session
        self.session_db.store_sessions(sessions)

    def load_sessions(self, session_id, tokens=[], **kwargs):
        return self.session_db.load_sessions(session_id, load_tokens=tokens, **kwargs)

    def _load_user_client_session(self, uid, client_id):
        client_key = self.endpoint_context.session_manager.session_key(uid, client_id)
        sessions = self.load_sessions(client_key)
        user_session = sessions[uid]
        client_session = sessions[client_key]
        self.endpoint_context.session_manager.load(
            {
                "db": {
                    uid: [
                        "idpyoidc.server.session.info.UserSessionInfo",
                        user_session.dump(),
                    ],
                    client_key: [
                        "idpyoidc.server.session.info.ClientSessionInfo",
                        client_session.dump(),
                    ],
                }
            }
        )
        return dict(user=user_session, client=client_session)

    def _load_session_from_token(self, token):
        token_info = self.endpoint_context.session_manager.token_handler.info(token)
        # Temporary work around. ID tokens don't return a token_class.
        # TODO: Remove this once fixed in idpyoidc
        if isinstance(token_info.get("handler"), OIDCIDToken):
            token_info["token_class"] = "id_token"

        sid = token_info.get("sid")
        compatible_sid = self.endpoint_context.session_manager._compatible_sid(sid)
        (
            uid,
            client_id,
            grant_id,
        ) = self.endpoint_context.session_manager.decrypt_session_id(compatible_sid)

        client_key = self.endpoint_context.session_manager.session_key(uid, client_id)
        grant_key = self.endpoint_context.session_manager.session_key(
            uid, client_id, grant_id
        )

        sessions = self.load_sessions(
            grant_key, tokens={token_info["token_class"]: [token]}
        )
        # Load the grant under its actual class. A token-exchange session
        # holds an ExchangeGrant, and loading it under the base Grant class
        # would silently drop exchange_request and the ExchangeGrant-specific
        # payload handling.
        grant_class = qualified_name(sessions[grant_key].__class__)
        self.endpoint_context.session_manager.load(
            {
                "db": {
                    uid: [
                        "idpyoidc.server.session.info.UserSessionInfo",
                        sessions[uid].dump(),
                    ],
                    client_key: [
                        "idpyoidc.server.session.info.ClientSessionInfo",
                        sessions[client_key].dump(),
                    ],
                    grant_key: [
                        grant_class,
                        sessions[grant_key].dump(),
                    ],
                    compatible_sid: [
                        grant_class,
                        sessions[grant_key].dump(),
                    ],
                }
            }
        )
        return dict(
            grant=sessions[grant_key],
            user=sessions[uid],
            client=sessions[client_key],
        )

    def _get_endpoint_path(self, endpoint=None, full_path=None):
        if full_path is None:
            endpoint = self.server.get_endpoint(endpoint)
            if endpoint is None:
                raise ValueError("A full_path or an endpoint must be published")
            full_path = endpoint.full_path
        if not full_path.startswith(self.base_url + "/"):
            raise Exception("Bad configuration, issuer doesn't start with base_url")
        # Remove base_url and slash
        return full_path[len(self.base_url) + 1 :]

    def register_endpoints(self, backend_names):
        """
        See super class satosa.frontends.base.FrontendModule
        :type backend_names: list[str]
        :rtype: list[(str, ((satosa.context.Context, Any) ->
            satosa.response.Response, Any))]
        :raise ValueError: if more than one backend is configured
        """
        # TODO: For now we always route to the first backend in the backend
        # list, we need to think how we will handle multiple backends
        self.target_backend = backend_names[0]

        # .well-known/openid-configuration endpoint
        provider_config = (
            "^{}$".format(self._get_endpoint_path("provider_config")),
            self.handle_provider_info,
        )

        # authorization endpoint
        authorization = (
            "^{}$".format(self._get_endpoint_path("authorization")),
            self.handle_authn_request,
        )

        # jwks endpoint
        jwks = (
            "^{}$".format(
                self._get_endpoint_path(
                    full_path=self.server.context.get_preference("jwks_uri")
                )
            ),
            self.handle_jwks,
        )

        url_map = [provider_config, authorization, jwks]

        # registration endpoint
        if "registration" in self.provider_config["endpoint"]:
            registration = (
                "^{}$".format(self._get_endpoint_path("registration")),
                self.handle_registration,
            )
            url_map.append(registration)

        if "token" in self.provider_config["endpoint"]:
            # token endpoint
            token = ("^{}$".format(self._get_endpoint_path("token")), self.handle_token)
            url_map.append(token)

        if "userinfo" in self.provider_config["endpoint"]:
            # userinfo endpoint
            userinfo = (
                "^{}$".format(self._get_endpoint_path("userinfo")),
                self.handle_userinfo,
            )
            url_map.append(userinfo)

        # introspection endpoint
        if "introspection" in self.provider_config["endpoint"]:
            introspection = (
                "^{}$".format(self._get_endpoint_path("introspection")),
                self.handle_introspection,
            )
            url_map.append(introspection)

        # revocation endpoint
        if "token_revocation" in self.provider_config["endpoint"]:
            revocation = (
                "^{}$".format(self._get_endpoint_path("token_revocation")),
                self.handle_token_revocation,
            )
            url_map.append(revocation)

        return url_map

    def make_response(self, endpoint, args, resp_class):
        """
        Takes an endpoint the args returned from process_request and the
        class to be used for responding and returns an instance of the
        response.
        :type endpoint: idpyoidc.endpoint.Endpoint
        :type args: Mapping
        :type resp_class: satosa.response.Response
        :rtype: satosa.response.Response

        :param endpoint: the endpoint to be used.
        :param args: A dict with args to be passed to the endpoints
            `do_response` function, usually produced from `process_request`.
        :param resp_class: a class used to construct the response.
        :return: HTTP response to the client
        """
        resp = endpoint.do_response(**args)
        headers = dict(resp["http_headers"])
        content = headers.pop("Content-type", None)
        headers = list(headers.items())
        assert isinstance(args, Mapping)
        assert "error" not in args or "error" in resp["response"]
        assert resp_class is not Redirect or type(resp["response"]) is str
        if "error" in args:
            log_report = {
                "message": "BadRequest set",
                "endpoint": endpoint,
                "response params": args,
                "initial response type": resp_class,
            }
            logger.debug(log_report)
            resp_class = BadRequest
        return resp_class(resp["response"], headers=headers, content=content)

    def authentication_error_response(self, error, request, redirect=True):
        """
        Make an authorization error response

        :type error: dict
        :type request: dict
        :type redirect: boolean
        :rtype: satosa.response.Response

        :param error: The error response body (MUST contain "error" and SHOULD include
            "error_description")
        :param request: The authorization request, used to retrieve the state and the
            redirect_uri (if needed)
        :param redirect: Whether to redirect or not, if this is True then redirect_uri
            must be in the request, else a server_error is returned
        """
        state = request.get("state")
        if state:
            error["state"] = state

        if not redirect:
            return BadRequest(error, content="application/json")

        if "redirect_uri" not in request:
            error.update(
                {
                    "error": "server_error",
                    "error_description": "Data missing from session",
                },
            )
            return BadRequest(error, content="application/json")

        redirect_uri = request["redirect_uri"]
        endpoint = self.server.get_endpoint("authorization")
        redirect_uri = endpoint.error_cls(**error).request(redirect_uri)
        return Redirect(redirect_uri)

    def parse_request(
        self,
        endpoint,
        context,
        error_cls=BadRequest,
        request=None,
        request_authorization=None,
    ):
        request = request or context.request
        request_authorization = request_authorization or context.request_authorization
        try:
            if request_authorization == "":
                request_authorization = None
            parsed_request = endpoint.parse_request(
                request, {"headers": {"authorization": request_authorization}}
            )
        except exception.ClientAuthenticationError as e:
            msg = "Error in authn req: {}".format(str(e))
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.error(logline)

            error_resp = TokenErrorResponse(
                error="invalid_client", error_description=str(e)
            )
            return BadRequest(
                error_resp.to_json(),
                content="application/json",
            )
        except (exception.BearerTokenAuthenticationError, exception.ToOld) as e:
            error_resp = TokenErrorResponse(
                error="invalid_token", error_description=e.args[0]
            )
            return Unauthorized(
                error_resp.to_json(),
                headers=[("WWW-Authenticate", "Bearer")],
                content="application/json",
            )

        if "error" in parsed_request:
            logger.error(
                "Error in authn req: {}".format(parsed_request["error_description"])
            )
            # Perhaps we should have a more sophisticated mapping between error
            # and error class, maybe we should have a map between endpoint,
            # error and class?
            # This simple approach seems to be fine so far...
            return error_cls(parsed_request.to_json(), content="application/json")

        return parsed_request

    def _add_context_data(self, request, client_id, context):
        """
        Get the client metadata, strip away some information and store it in
        the context
        """
        client_metadata = {
            k: v
            for k, v in self.endpoint_context.cdb[client_id].items()
            if k not in ["client_secret", "client_salt"]
        }
        context.decorate(KEY_REQUESTER_METADATA, client_metadata)
        context.state[self.name] = dict(oidc_request=request)

    def _get_approved_attributes(self, authn_req):
        claims_interface = self.endpoint_context.claims_interface
        # Get the claims, we have to flatten a dict of lists
        claims = functools.reduce(
            iconcat,
            (
                list(v.keys())
                for v in claims_interface.get_claims_all_usage_from_request(
                    authn_req
                ).values()
            ),
        )
        return set(available_claims(self.server.context)).intersection(set(claims))

    def _handle_authn_request(self, context):
        """
        Parse and verify the authentication request into an internal request.
        :type context: satosa.context.Context
        :rtype: satosa.internal.InternalData

        :param context: the current context
        :return: the internal request
        """
        request = context.request
        msg = "Authn req from client: {}".format(request)
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)
        client_id = request.get("client_id")
        try:
            self.endpoint_context.cdb = self.client_db
        except Exception:
            pass

        endpoint = self.server.get_endpoint("authorization")

        # Ensure that when the 'offline_access' scope is requested,
        # the 'prompt' parameter is set to 'consent' if it is not already present.
        scopes = request.get("scope", "").strip().split()
        if "offline_access" in scopes and "prompt" not in request:
            request["prompt"] = "consent"

        parsed_request = self.parse_request(endpoint, context)
        if isinstance(parsed_request, (Unauthorized, BadRequest)):
            return parsed_request

        try:
            self._remove_unknown_scopes(parsed_request, context)
        except ValueError:
            err_dscr = "The requested scope is invalid, unknown, or malformed."
            error = {
                "error": "invalid_scope",
                "error_description": err_dscr,
            }
            return self.authentication_error_response(error, request, redirect=True)
        
        if parsed_request["scope"] == [""] or "openid" not in parsed_request["scope"]:
            logger.error(
                f"`openid` not in the `allowed_scopes` for the client: {client_id}"
            )
            err_dscr = "The requested scope is invalid, unknown, or malformed."
            error = {
                "error": "invalid_scope",
                "error_description": err_dscr,
            }
            return self.authentication_error_response(error, request, redirect=True)

        self._add_context_data(request, client_id, context)

        # Defaults to pairwise
        subject_type = self.endpoint_context.cdb[client_id].get(
            "subject_type", "pairwise"
        )
        client_name = self.endpoint_context.cdb[client_id].get("client_name")
        if client_name:
            # TODO should process client names for all languages, see
            # OIDC Registration, Section 2.1
            client_name = [{"lang": "en", "text": client_name}]
        else:
            client_name = None
        internal_req = InternalData(
            subject_type=subject_type,
            requester=client_id,
            requester_name=client_name,
        )
        acr_values_param = (request.get("acr_values") or "").split()
        acr_values_claims_param = request.get("claims", {}).get("id_token", {}).get("acr", {}).get("values") or []
        acr_values_claims_param = acr_values_claims_param if isinstance(acr_values_claims_param, list) else [acr_values_claims_param]

        # Return error when both acr_values and the claims param
        # for an acr value in the same request are requested.
        if acr_values_param and acr_values_claims_param:
            logger.error(
                f"acr_values and the claims param for acr value are requested in the same request"
            )
            err_dscr = "The request had both acr_values and the claims param for acr value"
            error = {
                "error": "access_denied",
                "error_description": err_dscr,
            }
            return self.authentication_error_response(error, request, redirect=True)

        # Check if there is a configuration for ACR
        acr_values_client_config = self.endpoint_context.cdb[client_id].get("requested_acrs") or []
        acr_values = acr_values_client_config or acr_values_param or acr_values_claims_param
        if acr_values:
            internal_req.auth_info.auth_class_ref = acr_values

        internal_req.attributes = self.converter.to_internal_filter(
            "openid", self._get_approved_attributes(parsed_request)
        )

        return internal_req

    @session_manager_dump
    def handle_authn_request(self, context):
        """
        Handle an authentication request and pass it on to the backend.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        context.target_backend = self.target_backend
        internal_req = self._handle_authn_request(context)
        if not isinstance(internal_req, InternalData):
            return internal_req
        return self.auth_req_callback_func(context, internal_req)

    def handle_provider_info(self, context):
        """
        Handle .well-known/openid-configuration requests.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.server.get_endpoint("provider_config")
        args = endpoint.process_request()
        return self.make_response(endpoint, args, Response)

    @session_manager_dump
    @check_request_method(allowed_request_methods=["POST"])
    def handle_registration(self, context):
        """
        Handle registration requests.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        # The response_types parameter is a JSON object, idpyoidc does not
        # parse it properly.
        # TODO: This should be handled in idpyoidc
        if "response_types" in context.request and isinstance(
            context.request["response_types"], str
        ):
            try:
                context.request["response_types"] = json.loads(
                    context.request["response_types"]
                )
            except json.decoder.JSONDecodeError:
                return BadRequest("response_types is not a valid JSON.")
        endpoint = self.server.get_endpoint("registration")
        if context.request_authorization:
            token = get_token_from_header(context.request_authorization)
            try:
                self._load_session_from_token(token)
            except Exception:
                pass
        parsed_request = self.parse_request(endpoint, context)
        if isinstance(parsed_request, (Unauthorized, BadRequest)):
            return parsed_request

        args = endpoint.process_request(request=parsed_request)
        ret = self.make_response(endpoint, args, Created)

        self.client_db.update(self.endpoint_context.cdb)
        return ret

    @session_manager_dump
    @check_request_method(allowed_request_methods=["POST", "GET"])
    def handle_userinfo(self, context):
        """
        Handle userinfo requests.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.server.get_endpoint("userinfo")
        parsed_request = self.parse_request(endpoint, context, error_cls=Unauthorized)
        if isinstance(parsed_request, Unauthorized):
            return parsed_request
        at = get_token_from_header(context.request_authorization)
        self.log_request(
            context,
            endpoint="Userinfo",
            access_token=at,
        )
        try:
            self._load_session_from_token(at)
        except Exception:
            pass

        args = endpoint.process_request(request=parsed_request)

        msg = "{} endpoint response={}".format(endpoint, args)
        satosa_session_id = lu.get_session_id(context.state)
        logline = lu.LOG_FMT.format(
            id=satosa_session_id,
            message=msg,
        )
        logger.info(logline)

        if "error" not in args:
            for hook in self.userinfo_post_process_hooks:
                hook(args, parsed_request, parsed_request.get("access_token"), context)
        return self.make_response(endpoint, args, Response)

    @session_manager_dump
    @check_request_method(allowed_request_methods=["POST"])
    def handle_introspection(self, context):
        """
        Handle introspection requests.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.server.get_endpoint("introspection")
        parsed_request = self.parse_request(endpoint, context)
        if isinstance(parsed_request, (Unauthorized, BadRequest)):
            return parsed_request
        self.log_request(
            context, endpoint="Introspection", access_token=parsed_request["token"]
        )

        try:
            self._load_session_from_token(parsed_request["token"])
        except Exception:
            pass
        args = endpoint.process_request(request=parsed_request)

        for hook in self.introspection_post_process_hooks:
            args = hook(args, parsed_request, parsed_request["token"], context)

        msg = "{} endpoint response={}".format(
            endpoint, args["response_args"].to_json()
        )
        satosa_session_id = lu.get_session_id(context.state)
        logline = lu.LOG_FMT.format(
            id=satosa_session_id,
            message=msg,
        )
        logger.info(logline)

        return self.make_response(endpoint, args, Response)

    @session_manager_dump
    @check_request_method(allowed_request_methods=["POST"])
    def handle_token_revocation(self, context):
        """
        Handle revocation requests.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.server.get_endpoint("token_revocation")
        parsed_request = self.parse_request(endpoint, context)
        if isinstance(parsed_request, (Unauthorized, BadRequest)):
            return parsed_request
        self.log_request(
            context, endpoint="Revocation", access_token=parsed_request["token"]
        )

        try:
            self._load_session_from_token(parsed_request["token"])
        except Exception:
            pass
        args = endpoint.process_request(request=parsed_request)

        # for hook in self.introspection_post_process_hooks:
        #     args = hook(args, parsed_request, context)

        return self.make_response(endpoint, args, Response)

    @session_manager_dump
    @check_request_method(allowed_request_methods=["POST"])
    def handle_token_revocation(self, context):
        """
        Handle revocation requests.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.server.get_endpoint("token_revocation")
        parsed_request = self.parse_request(endpoint, context)
        if isinstance(parsed_request, (Unauthorized, BadRequest)):
            return parsed_request
        self.log_request(
            context, endpoint="Revocation", access_token=parsed_request["token"]
        )

        try:
            self._load_session_from_token(parsed_request["token"])
        except Exception:
            pass
        args = endpoint.process_request(request=parsed_request)

        # for hook in self.introspection_post_process_hooks:
        #     args = hook(args, parsed_request, context)

        return self.make_response(endpoint, args, Response)

    @session_manager_dump
    def handle_authn_response(self, context, internal_resp):
        """
        See super class method
        satosa.frontends.base.FrontendModule#handle_authn_response
        :type context: satosa.context.Context
        :type internal_response: satosa.internal.InternalData
        :rtype satosa.response.Response
        """
        endpoint = self.server.get_endpoint("authorization")
        try:
            auth_req = context.state[self.name]["oidc_request"]
        except KeyError:
            """
            If we end up here, it means that the user returns to the proxy
            without the SATOSA session cookie. This can happen at least in the
            following cases:
            - the user deleted the cookie from the browser
            - the browser of the user blocked the cookie
            - the user has completed an authentication flow, the cookie has
              been removed by SATOSA and then the user used the back button
              of their browser and resend the authentication response, but
              without the SATOSA session cookie
            """
            error = "Received AuthN response without a SATOSA session cookie"
            raise SATOSAMissingStateError(error)

        client_id = auth_req.get("client_id")
        try:
            self.endpoint_context.cdb[client_id] = self.client_db[client_id]
        except Exception:
            pass
        auth_req["response_type"] = auth_req["response_type"].split(" ")
        # TODO: Remove this conversion after it is fixed in idpyoidc, the library
        # should be responsible for parsing the request
        if "scope" in auth_req:
            auth_req["scope"] = auth_req["scope"].split(" ")
        parsed_request = self.parse_request(endpoint, context, request=auth_req)
        if isinstance(parsed_request, (Unauthorized, BadRequest)):
            return parsed_request
        attributes = self.converter.from_internal("openid", internal_resp.attributes)

        sub = attributes.get("sub", [None])[0]

        if not sub:
            error = {
                "error": "access_denied",
                "error_description": "No sub retrieved for user",
            }
            message = "No sub found in the user's attributes"
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=message
            )
            logger.error(logline)
            return self.authentication_error_response(error, auth_req, redirect=True)

        try:
            # We try to load the session, if it exists. This might be the first login
            # for this user/client, in this case idpyoidc will create a session later
            self._load_user_client_session(sub, client_id)
        except Exception:
            pass

        self.user_db[sub] = dict(combine_claim_values(attributes.items()))
        
        client_info = self.endpoint_context.cdb[client_id]
        acr_values_client_config = client_info.get("requested_acrs") or []
        acr_values_param = (auth_req.get("acr_values") or "").split()
        acr_values_claims_param = auth_req.get("claims", {}).get("id_token", {}).get("acr", {}).get("values") or []
        acr_values_claims_param = acr_values_claims_param if isinstance(acr_values_claims_param, list) else [acr_values_claims_param]
        
        acr_essential = auth_req.get("claims", {}).get("id_token", {}).get("acr", {}).get("essential", False)
        response_acr = None
        if acr_values_client_config or acr_values_param or acr_values_claims_param:
            response_acr = getattr(internal_resp.auth_info, "auth_class_ref", None)
        # Check if response_acr exists in any of the acr lists, prioritizing order
        if acr_values_client_config:
             # ACRs from the configuration are considered essential
            is_acr_satisfied = response_acr in acr_values_client_config
        elif acr_values_param:
            # The ACR is optional (not essential) when `acr_values` is used; thus it is always satisfied.
            is_acr_satisfied = True
        elif acr_values_claims_param:
            is_acr_satisfied = not acr_essential or response_acr in acr_values_claims_param
        else:
            # No ACR values were set as required or requested
            is_acr_satisfied = True

        if not is_acr_satisfied:      
            log_report = {
                "message": "Requested ACR not satisfied",
                "acr_values_client_config": acr_values_client_config,
                "acr_values_param": acr_values_param,
                "acr_values_claims_param": acr_values_claims_param,
                "is_acr_satisfied": is_acr_satisfied,
            }
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=log_report
            )
            logger.error(logline)
            error = {
                "error": "access_denied",
                "error_description": "Requested ACR not satisfied",
            }
            return self.authentication_error_response(error, auth_req, redirect=True)

        authn_event = create_authn_event(sub, authn_info = response_acr)
        sid = self.endpoint_context.session_manager.create_session(
            authn_event,
            parsed_request,
            sub,
            parsed_request["client_id"],
            "public",
            token_usage_rules=self.endpoint_context.authz.usage_rules(
                parsed_request["client_id"]
            ),
        )

        args = endpoint.authz_part2(parsed_request, sid)

        if "session_id" in args:
            self.log_request(
                context,
                endpoint="Authentication",
                session_id=args["session_id"],
            )

        # Clear cookie
        del context.state[self.name]
        # If response_method == 'post'
        if "response_msg" in args:
            return self.make_response(endpoint, args, Response)
        else:
            return self.make_response(endpoint, args, Redirect)

    def handle_backend_error(self, exception):
        """
        See super class satosa.frontends.base.FrontendModule
        :type exception: satosa.exception.SATOSAError
        :rtype: satosa.response.Response
        """
        auth_req = exception.state[self.name]["oidc_request"]
        if "state" in auth_req:
            error_resp = AuthorizationErrorResponse(
                error="access_denied",
                error_description=exception.message,
                state=auth_req["state"],
            )
        else:
            error_resp = AuthorizationErrorResponse(
                error="access_denied", error_description=exception.message
            )

        logline = lu.LOG_FMT.format(
            id=lu.get_session_id(exception.state), message=exception.message
        )
        logger.debug(logline)
        # This doesn't look very clean
        return Redirect(
            error_resp.request(auth_req["redirect_uri"], fragment_encoding(auth_req))
        )

    @session_manager_dump
    @check_request_method(allowed_request_methods=["POST"])
    def handle_token(self, context):
        """
        Handle token requests.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        endpoint = self.server.get_endpoint("token")
        try:
            self.endpoint_context.cdb = self.client_db
        except Exception:
            pass
        grant_type = context.request.get("grant_type")
        # grant_types_supported = endpoint.kwargs.get("grant_types_supported", list(self.helper.keys()))
        # grant_types_supported = client.get("grant_types_supported", self.grant_types_supported)
        if grant_type in endpoint.kwargs.get("grant_types_helpers"):
            if grant_type == "client_credentials":
                pass
            else:
                try:
                    if grant_type == "authorization_code":
                        token = context.request["code"]
                    elif (
                        grant_type == "urn:ietf:params:oauth:grant-type:token-exchange"
                    ):
                        token = context.request["subject_token"]
                    elif grant_type == "refresh_token":
                        token = context.request["refresh_token"]
                    self._load_session_from_token(token)
                except Exception:
                    pass
        else:
            return BadRequest("invalid_request")

        parsed_request = self.parse_request(endpoint, context)
        if isinstance(parsed_request, (Unauthorized, BadRequest)):
            return parsed_request

        if (
            "scope" in context.request
            and grant_type == "urn:ietf:params:oauth:grant-type:token-exchange"
        ):
            try:
                self._remove_unknown_scopes(parsed_request, context)
            except ValueError:
                err_dscr = "The requested scope is invalid, unknown, or malformed."
                error = {
                    "error": "invalid_scope",
                    "error_description": err_dscr,
                }
                return BadRequest(json.dumps(error), content="application/json")

        self.log_request(
            context,
            endpoint="Token",
            code=parsed_request.get("code"),
            refresh_token=parsed_request.get("refresh_token"),
            access_token=parsed_request.get("subject_token"),
        )
        args = endpoint.process_request(request=parsed_request)
        return self.make_response(endpoint, args, Response)

    def handle_jwks(self, context):
        """
        Handle jwks requests.
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        jwks = self.endpoint_context.keyjar.export_jwks_as_json()
        return Response(jwks, content="application/json")

    def _remove_unknown_scopes(self, request, context):
        """
        Enforce unknown scopes policy.
        If deny_unknown_scopes is True an exception will be thrown.
        Otherwise the unknown scopes will be filtered.
        :type request: dict
        :type context: satosa.context.Context
        :rtype: satosa.response.Response

        :param context: the current context
        :return: HTTP response to the client
        """
        client_id = request.get("client_id")
        try:
            authorization.check_unknown_scopes_policy(
                request, client_id, self.endpoint_context
            )
            filtered_scopes = self.endpoint_context.scopes_handler.filter_scopes(
                request["scope"], client_id
            )
        except exception.UnAuthorizedClientScope as e:
            msg = "Requested unknown scopes: {}".format(str(e))
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.error(logline)
            raise ValueError()

        context.request["scope"] = " ".join(filtered_scopes)
        request["scope"] = context.request["scope"]


@contextmanager
def session_scope(Session, commit=True):
    """Provide a transactional scope around a series of operations."""
    session = Session()
    try:
        yield session
        if commit:
            session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def call_with_retry(f):
    # Used to call a function and retry if a certain exception is caught, this is
    # used to solve the error created when the connection to the db closes, which
    # causes the first query to fail
    #
    # WARNING: This should not be used with functions performing more than one
    # operations, since it could result in some of them happening more than once
    # TODO: Make configurable
    @functools.wraps(f)
    def wrapper(self, *args, retries=2, exc=SQLAlchemyError, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except exc as e:
            logger.info("DB query failed with error: {}".format(e))
            if retries > 0:
                logger.debug("Retrying query")
                return wrapper(self, *args, retries=retries - 1, **kwargs)
            raise

    return wrapper


class ClientDB(ClientSource):
    def __init__(self):
        self.session_maker = sessionmaker(bind=engine)

    @call_with_retry
    def __getitem__(self, client_id):
        with session_scope(self.session_maker, commit=False) as session:
            q = session.query(Client)
            client = q.filter_by(client_id=client_id).first()
        if not client:
            raise KeyError
        return client.client_info

    @call_with_retry
    def __contains__(self, client_id):
        with session_scope(self.session_maker, commit=False) as session:
            q = session.query(Client).filter_by(client_id=client_id)
            exists = session.query(q.exists()).scalar()
        return exists

    @call_with_retry
    def __setitem__(self, client_id, client_info):
        with session_scope(self.session_maker) as session:
            updated = (
                session.query(Client)
                .filter(Client.client_id == client_id)
                .update({"client_info": client_info})
            )
            if not updated:
                session.add(Client(client_id=client_id, client_info=client_info))

    def get(self, client_id, default={}):
        try:
            client_info = self[client_id]
        except KeyError:
            return default
        return client_info

    def set(self, client_id, client_info):
        self[client_id] = client_info

    def keys(self):
        with session_scope(self.session_maker, commit=False) as session:
            results = session.query(Client).all()
        for c in results:
            yield c.client_id

    def update(self, clients):
        with session_scope(self.session_maker) as session:
            for client_id, client_info in clients.items():
                updated = (
                    session.query(Client)
                    .filter(Client.client_id == client_id)
                    .update({"client_info": client_info})
                )
                if not updated:
                    session.add(Client(client_id=client_id, client_info=client_info))


class ClientSecretHashVerifier:
    def __init__(self, hashed_secret: str) -> None:
        self.hashed_secret = hashed_secret

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, str):
            return False

        return bcrypt.checkpw(
            __value.encode(),
            self.hashed_secret.encode(),
        )

    def __hash__(self) -> int:
        return hash(self.hashed_secret)


class ClientDBHashedSecrets(ClientDB):

    def __init__(self, db_uri=None):
        if engine and (not db_uri or engine.url == db_uri):
            # Use global engine if separate db_uri is not provided
            # or is the same as global config db_uri
            self.session_maker = sessionmaker(bind=engine)
        else:
            # Otherwise, create separate engine
            self.engine = create_engine(db_uri, echo=False)
            self.session_maker = sessionmaker(bind=self.engine)


    def _set_item_in_session(self, client_id, client_info, session):
        # Create copy of client_info to avoid accidental
        # mutation if it's used elsewhere
        processed_client_info = dict(client_info)

        if isinstance(
            client_info.get("client_secret"),
            ClientSecretHashVerifier,
        ):
            # Use hashed secret directly when storing to DB
            processed_client_info["client_secret"] = processed_client_info[
                "client_secret"
            ].hashed_secret

        updated = (
            session.query(Client)
            .filter(Client.client_id == client_id)
            .update({"client_info": processed_client_info})
        )

        if not updated:
            session.add(
                Client(
                    client_id=client_id,
                    client_info=processed_client_info,
                )
            )

    @call_with_retry
    def __getitem__(self, client_id):
        with session_scope(self.session_maker, commit=False) as session:
            q = session.query(Client)
            client = q.filter_by(client_id=client_id).first()
        if not client:
            raise KeyError

        client_info = client.client_info

        if client_info.get("client_secret") is not None:
            # Wrap hashed secret to check for equality
            client_info["client_secret"] = ClientSecretHashVerifier(
                client_info["client_secret"]
            )

        return client_info

    @call_with_retry
    def __setitem__(self, client_id, client_info):
        with session_scope(self.session_maker) as session:
            self._set_item_in_session(client_id, client_info, session)

    def update(self, clients):
        with session_scope(self.session_maker) as session:
            for client_id, client_info in clients.items():
                self._set_item_in_session(client_id, client_info, session)


class UserInfoDB:
    def __init__(self):
        self.session_maker = sessionmaker(bind=engine)

    @call_with_retry
    def __getitem__(self, user_id):
        with session_scope(self.session_maker, commit=False) as session:
            q = session.query(User)
            user = q.filter_by(user_id=user_id).first()
        if not user:
            raise KeyError
        return user.user_info

    @call_with_retry
    def __setitem__(self, user_id, user_info):
        with session_scope(self.session_maker) as session:
            updated = (
                session.query(User)
                .filter(User.user_id == user_id)
                .update({"user_info": user_info})
            )
            if not updated:
                session.add(User(user_id=user_id, user_info=user_info))

    def items(self):
        with session_scope(self.session_maker, commit=False) as session:
            results = session.query(User).all()
        return [(u.user_id, u.user_info) for u in results]


class SessionDB:
    token_map = {
        "authorization_code": "idpyoidc.server.session.token.AuthorizationCode",
        "access_token": "idpyoidc.server.session.token.AccessToken",
        "refresh_token": "idpyoidc.server.session.token.RefreshToken",
        "id_token": "idpyoidc.server.session.token.IDToken",
    }

    def __init__(self, session_manager=None):
        self.session_maker = sessionmaker(bind=engine)
        self.session_manager = session_manager

    def _unpack_session_key(self, session_id):
        sids = self.session_manager.unpack_session_key(session_id)
        client_id = grant_id = None
        if len(sids) == 1:
            user_id = sids[0]
        elif len(sids) == 2:
            user_id, client_id = sids
        elif len(sids) == 3:
            user_id, client_id, grant_id = sids
        else:
            raise ValueError("Unknown sid format")
        return user_id, client_id, grant_id

    def serialize_token(self, token, user_id, client_id, grant_id, scope=None):
        token_args = token.dump()
        token_value = token_args.pop("value")
        if not scope:
            scope = token.scope

        serialized = dict(
            token_id=token.id,
            token_value=token_value,
            token_args=token_args,
            grant_id=grant_id,
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            revoked=token.revoked,
            expires_at=token.expires_at,
        )
        if token.token_class == "access_token":
            serialized["token_type"] = token_args["token_type"]
        if token.token_class != "authorization_code":
            if "based_on" in token_args:
                serialized["based_on"] = token_args.get("based_on")
        return serialized

    def serialize_user_session(self, user):
        return dict(
            user_id=user.id,
            revoked=user.revoked,
        )

    def serialize_client_session(self, client, user_id):
        return dict(
            user_id=user_id,
            client_id=client.id,
            revoked=client.revoked,
        )

    def serialize_grant_info(self, grant_info):
        if "authentication_event" in grant_info:
            # We remove the class path from the dump
            grant_info["authentication_event"] = list(
                grant_info["authentication_event"].values()
            )[0]
        if "authorization_request" in grant_info:
            # We remove the class path from the dump
            grant_info["authorization_request"] = list(
                grant_info["authorization_request"].values()
            )[0]
        grant_info.pop("token_map", None)
        return grant_info

    def serialize_grant_session(self, grant, user_id, client_id):
        return dict(
            user_id=user_id,
            client_id=client_id,
            grant_id=grant.id,
            grant_info=self.serialize_grant_info(grant.dump()),
            grant_type=grant.type,
        )

    def deserialize_user_session(self, user):
        return UserSessionInfo(
            id=user.user_id,
            revoked=user.revoked,
        )

    def deserialize_client_session(self, client):
        return ClientSessionInfo(
            id=client.client_id,
            revoked=client.revoked,
        )

    def deserialize_grant_info(self, grant_info, tokens):
        grant_info["issued_token"] = [
            {
                token_class_to_str(token.name): {
                    "value": token.token_value,
                    **token.token_args,
                }
            }
            for token in tokens
        ]
        authentication_event = grant_info.get("authentication_event", {})
        if "oidcop.authn_event.AuthnEvent" in authentication_event:
            # Backwards compatability
            authentication_event = authentication_event["oidcop.authn_event.AuthnEvent"]

        authorization_request = grant_info.get("authorization_request", {})
        if "oidcmsg.oidc.AuthorizationRequest" in authorization_request:
            # Backwards compatability
            authorization_request = authorization_request[
                "oidcmsg.oidc.AuthorizationRequest"
            ]

        grant_info["authentication_event"] = {
            "idpyoidc.server.authn_event.AuthnEvent": authentication_event
        }
        grant_info["authorization_request"] = {
            "idpyoidc.message.oidc.AuthorizationRequest": authorization_request
        }
        grant_info["token_map"] = self.token_map
        return grant_info

    def deserialize_grant_session(self, grant, tokens):
        grant_class = {
            Grant.type: Grant,
            ExchangeGrant.type: ExchangeGrant,
        }.get(grant.grant_type, Grant)
        session_info = self.deserialize_grant_info(grant.grant_info, tokens)

        ret = grant_class().load(session_info)
        ret.id = grant.grant_id
        return ret

    def load_user_session(self, user_id, db_session):
        q = db_session.query(UserSession)
        session = q.filter_by(user_id=user_id).first()
        if not session:
            raise KeyError
        return session

    def load_client_session(self, user_id, client_id, db_session):
        q = db_session.query(ClientSession)
        session = q.filter_by(user_id=user_id, client_id=client_id).first()
        if not session:
            raise KeyError
        return session

    def load_grant_session(self, user_id, client_id, grant_id, db_session):
        q = db_session.query(GrantSession)
        session = q.filter_by(
            user_id=user_id, client_id=client_id, grant_id=grant_id
        ).first()
        if not session:
            raise KeyError
        return session

    def load_tokens(self, token_cls, tokens, db_session, user_id, client_id, grant_id):
        token_cls = {
            "authorization_code": AuthorizationCode,
            "access_token": AccessToken,
            "id_token": IDToken,
            "refresh_token": RefreshToken,
        }[token_cls]

        q = db_session.query(token_cls)
        token_args = false()
        for token in tokens:
            # We perform a different query depending on the token_type because
            # different indexes are used for each token
            if token_cls is AuthorizationCode:
                token_args = or_(
                    token_args,
                    token_cls.token_value == token,
                )
            elif token_cls is RefreshToken:
                token_args = or_(
                    token_args,
                    token_cls.token_value == token,
                )
            elif token_cls is AccessToken:
                if db_session.bind.dialect.name == "postgresql":
                    # We use hash of the token_value in order to use use an index scan
                    # instead of a sequential one, we still make sure the token_values
                    # match in case of a (unlikely) collision
                    token_args = or_(
                        token_args,
                        and_(
                            func.cast(func.md5(token_cls.token_value), UUID)
                            == func.cast(func.md5(token), UUID),
                            token_cls.token_value == token,
                        ),
                    )
                else:
                    # SQLite does not support md5
                    token_args = or_(
                        token_args,
                        token_cls.token_value == token,
                    )
            elif token_cls is IDToken:
                token_args = or_(
                    token_args,
                    and_(
                        token_cls.user_id == user_id,
                        token_cls.client_id == client_id,
                        token_cls.grant_id == grant_id,
                        token_cls.token_value == token,
                    ),
                )

        return q.filter(token_args).all()

    def store_user_session(self, session_info, db_session):
        updated = (
            db_session.query(UserSession)
            .filter(UserSession.user_id == session_info["user_id"])
            .update(session_info)
        )
        if not updated:
            db_session.add(UserSession(**session_info))

    def store_client_session(self, session_info, db_session):
        updated = (
            db_session.query(ClientSession)
            .filter(
                ClientSession.user_id == session_info["user_id"],
                ClientSession.client_id == session_info["client_id"],
            )
            .update(session_info)
        )
        if not updated:
            db_session.add(ClientSession(**session_info))

    def store_grant_session(self, session_info, db_session):
        updated = (
            db_session.query(GrantSession)
            .filter(
                GrantSession.user_id == session_info["user_id"],
                GrantSession.client_id == session_info["client_id"],
                GrantSession.grant_id == session_info["grant_id"],
            )
            .update(session_info)
        )
        if not updated:
            db_session.add(GrantSession(**session_info))

    def store_token(self, token, db_session):
        token_cls = {
            "authorization_code": AuthorizationCode,
            "access_token": AccessToken,
            "id_token": IDToken,
            "refresh_token": RefreshToken,
        }[token["token_args"]["token_class"]]

        updated = (
            db_session.query(token_cls)
            .filter(
                token_cls.token_id == token["token_id"],
            )
            .update(token)
        )
        if not updated:
            db_session.add(token_cls(**token))

    def load_sessions(
        self,
        session_id,
        load_tokens={},
    ):
        """
        Gets a list of session ids, unpacks the session ids and fetches all the
        sessions (user, client and grant) associated with them.
        """
        sessions = {}
        user_id, client_id, grant_id = self._unpack_session_key(session_id)
        client = grant = None

        with session_scope(self.session_maker, commit=False) as db_session:
            # Fetch user session
            user_session = self.load_user_session(user_id, db_session)
            user = self.deserialize_user_session(user_session)

            # Fetch client session
            if client_id:
                client_session = self.load_client_session(
                    user_id, client_id, db_session
                )
                client = self.deserialize_client_session(client_session)

            # Fetch grant session
            if grant_id:
                grant_session = self.load_grant_session(
                    user_id, client_id, grant_id, db_session
                )
                tokens = []
                for token_class, token_values in load_tokens.items():
                    tokens.extend(
                        self.load_tokens(
                            token_class,
                            token_values,
                            db_session,
                            user_id,
                            client_id,
                            grant_id,
                        )
                    )
                grant = self.deserialize_grant_session(grant_session, tokens)

        if grant:
            sessions[self.session_manager.session_key(user_id, client_id, grant_id)] = (
                grant
            )
            client.subordinate.append(grant.id)
        if client:
            sessions[self.session_manager.session_key(user_id, client_id)] = client
            user.subordinate.append(client.id)
        sessions[self.session_manager.session_key(user_id)] = user

        return sessions

    def store_sessions(self, sessions):
        """
        Gets a dict of {session_id:session_info} and stores them in the database
        """
        user_sessions_to_store = []
        client_sessions_to_store = []
        grant_sessions_to_store = []
        issued_tokens = []
        tokens_to_store = []
        for key, session in sessions.items():
            user_id, client_id, grant_id = self._unpack_session_key(key)
            if isinstance(session, Grant):
                grant = session
                issued_tokens = session.issued_token
                session.issued_token = []
                grant_sessions_to_store.append(
                    self.serialize_grant_session(session, user_id, client_id)
                )
                for token in issued_tokens:
                    tokens_to_store.append(
                        self.serialize_token(
                            token,
                            user_id,
                            client_id,
                            grant_id,
                            scope=grant.find_scope(token),
                        )
                    )
            elif isinstance(session, ClientSessionInfo):
                session.subordinate = []
                client_sessions_to_store.append(
                    self.serialize_client_session(session, user_id)
                )
            elif isinstance(session, UserSessionInfo):
                session.subordinate = []
                user_sessions_to_store.append(self.serialize_user_session(session))

        with session_scope(self.session_maker) as db_session:
            for session_info in user_sessions_to_store:
                self.store_user_session(session_info, db_session)
            for session_info in client_sessions_to_store:
                self.store_client_session(session_info, db_session)
            for session_info in grant_sessions_to_store:
                self.store_grant_session(session_info, db_session)
            for token in tokens_to_store:
                self.store_token(token, db_session)


class SessionDict:
    def __init__(self):
        self.sessions = {}

    def load_sessions(self, session_ids, load_tokens=[], **kwargs):
        return dict(self.sessions)

    def store_sessions(self, sessions):
        self.sessions.update(sessions)


class AttributeAuth(ClientAuthnMethod):
    """
    A custom authentication method checking for Bearer header.
    Also allows checking for specific user attribute values before
    allowing access.

    It can be used for example as a registration_authn option in the
    configuration by setting:

    registration_authn:
        - satosa_oidc_frontend.AttributeAuth

    To configure AttributeAuth to check for attribute values put the
    following in the frontend config:

    attribute_auth:
        eduperson_scoped_affiliation:
            - staff@example.com
            - admin@example.com
        eduPersonTargetedID:
            - staffa
            - adminb

    This will require that the user authenticating has BOTH those attributes
    in her user_info with EITHER value set in the config for the respective
    attribute.
    """

    tag = "attributeauth"

    CHECK_FOR_ATTRIBUTES = False
    ATTRIBUTES = {}

    def is_usable(self, request=None, authorization_token=None):
        return authorization_token is not None and authorization_token.startswith(
            "Bearer "
        )

    def _verify(
        self,
        request=None,
        authorization_token=None,
        endpoint=None,
        **kwargs,
    ):
        endpoint_context = self.upstream_get("context")
        _mngr = endpoint_context.session_manager
        token = authorization_token[len("Bearer ") :]

        session_info = _mngr.get_session_info_by_token(token, grant=True)
        grant = session_info["grant"]
        for possible_token in grant.issued_token:
            if possible_token.value == token:
                token = possible_token

        # should be an access token And it should be valid
        if not isinstance(token, OIDCAccessToken) or token.is_active() is False:
            raise ClientAuthenticationError()

        # if the authenticate is still active or offline_access is granted.
        if grant.authentication_event["valid_until"] <= utc_time_sans_frac():
            raise ClientAuthenticationError()

        if self.CHECK_FOR_ATTRIBUTES:
            user_info = endpoint_context.userinfo(
                session_info["user_id"], client_id=None
            )
            for attr, attr_values in self.ATTRIBUTES.items():
                if attr not in user_info:
                    raise ClientAuthenticationError()
                if not any(
                    (
                        not isinstance(value, type(user_info[attr]))
                        and value in user_info[attr]
                    )
                    or value == user_info[attr]
                    for value in attr_values
                ):
                    raise ClientAuthenticationError()

        return {"client_id": session_info["client_id"]}


class RemoteIntrospection:
    def __init__(self, remote_introspection_providers=None):
        self.remote_introspection_providers = remote_introspection_providers
        self.validate_provider_configuration()

    def validate_provider_configuration(self):
        for provider_metadata in self.remote_introspection_providers.values():
            if (
                any(
                    attr not in provider_metadata
                    for attr in ("client_id", "client_secret", "endpoints")
                )
                or not provider_metadata["endpoints"]
            ):
                raise SATOSAConfigurationError(
                    "Missing info in remote_introspection_providers"
                )

    def get_issuer_from_jws(self, token):
        """
        Tries to extract the issuer from a possible JWS token.

        We don't implement full JWT validation for now, just some basic checks
        for JWT syntax.

        TODO: Allow adding PKs for each provider (or a well-known endpoint to
        get them) for proper validation before forwarding the introspection
        requests.
        """
        segments = token.split(".")
        if len(segments) != 3:
            return None

        b64_payload = segments[1]

        try:
            # payload in JWTs may not have full padding
            payload = b64decode(b64_payload + "=" * (-len(b64_payload) % 4))
            claims = json.loads(payload)
        except (binascii.Error, json.decoder.JSONDecodeError):
            return None

        return claims.get("iss")

    def make_authorization_header(self, client_id, client_secret):
        auth_string = "{}:{}".format(client_id, client_secret)
        return "Basic {}".format(str(b64encode(auth_string.encode("utf-8")), "utf-8"))

    def should_introspect(self, parsed_request, local_introspection_args):
        return (
            self.remote_introspection_providers
            and "error" not in parsed_request
            and not local_introspection_args["response_args"]["active"]
        )

    def __call__(self, local_introspection_args, parsed_request, token, context):
        """
        Introspects a token on other providers based on the config.

        This only happens if the introspection request is well-formed
        and found not active by us.

        Providers can be set under remote_introspection_providers in the OIDC
        frontend config. A provider will be chosen based on the iss claim of
        the JWT payload. In the case of non-JWT, unknown issuer or no issuser
        claim a fallback provider will be used.

        The format should be the following:

        remote_introspection_providers:
          "https://provider.example.com/":
            client_id: test
            client_secret: secr3t
            endpoints:
                - "https://provider.example.com/introspect"
         "":
            client_id: test
            client_secret: secr3t
            endpoints:
                - "https://provider2.example.com/introspect"
                - "https://provider2.example.com/introspect2"

        As seen by the config above, each provider can have multiple
        introspection endpoints set, to be used with the same credentials to
        get at least one active=True response.

        Also, setting "" as the issuer name, sets those credentials and
        endpoints as the fallback provider.
        """
        if not self.should_introspect(parsed_request, local_introspection_args):
            return local_introspection_args

        provider_to_try = self.remote_introspection_providers.get("", None)
        issuer = self.get_issuer_from_jws(token)
        if issuer:
            provider_to_try = self.remote_introspection_providers.get(
                issuer, provider_to_try
            )

        if not provider_to_try:
            return local_introspection_args

        headers = {}
        new_response = TokenIntrospectionResponse(active=False)

        client_id = provider_to_try["client_id"]
        client_secret = provider_to_try["client_secret"]
        endpoints = provider_to_try["endpoints"]

        headers["Authorization"] = self.make_authorization_header(
            client_id, client_secret
        )
        for endpoint in endpoints:
            msg = f"Remote introspection for token {token} at {endpoint}"
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.info(logline)

            try:
                remote_response = requests.post(
                    endpoint,
                    data={"token": token},
                    headers=headers,
                    timeout=3,
                )
                remote_response.raise_for_status()
                new_response = TokenIntrospectionResponse(**remote_response.json())
            except Exception as e:
                msg = f"Remote introspection error: {e}"
                logline = lu.LOG_FMT.format(
                    id=lu.get_session_id(context.state), message=msg
                )
                logger.error(logline)
                continue

            msg = f"Remote introspection response: {remote_response.text}"
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.info(logline)
            if new_response["active"]:
                break
        local_introspection_args["response_args"] = new_response
        return local_introspection_args

class RemoteDataProviderConfig(BaseModel):
    ignore_api_error: bool = False
    api_url: HttpUrl
    api_username: str
    api_password: SecretStr
    api_timeout: int
    api_retries: int
    require_scopes: Optional[List[str]] = None
    wrap_claim_name: Optional[str] = None
    
class RemoteDataProvider:
    def __init__(self, remote_endpoints=None):
        self.remote_endpoints = [
            RemoteDataProviderConfig(**endpoint) for endpoint in (remote_endpoints or [])
        ]

    def get_scopes_from_jws(self, token):
        """
        Tries to extract scopes from a possible JWS token.

        We don't implement full JWT validation for now, just some basic checks
        for JWT syntax.
        """
        segments = token.split(".")
        if len(segments) != 3:
            return None

        b64_payload = segments[1]

        try:
            # payload in JWTs may not have full padding
            payload = b64decode(b64_payload + "=" * (-len(b64_payload) % 4))
            p = json.loads(payload)
        except (binascii.Error, json.decoder.JSONDecodeError):
            return None

        scopes = p.get("scope")
        return scopes.split(" ") if scopes else None

    def __call__(self, local_args, parsed_request, token, context):
        """
        Probes a remote data provider endpoint.

        Providers can be set under remote_endpoints in the OIDC
        frontend config.

        The format should be the following:

        "remote_endpoints": [ 
            {
                "require_scopes": ["openid"],
                "wrap_claim_name": "my_custom_claim",
                "ignore_api_error": False,
                "api_url": "https://provider2.example.com/userinfo",
                "api_username": "foo",
                "api_password": "bar",
                "api_timeout": 60,
                "api_retries": 3
            }
        ]
        """
        for endpoint_config in self.remote_endpoints:
            if not endpoint_config:
                return local_args

            scopes = list(set(self.get_scopes_from_jws(token) or []).intersection(set(endpoint_config.require_scopes or [])))
            if not scopes and endpoint_config.require_scopes:
                # ignore this endpoint
                continue

            session = requests.Session()
            # Set basic authentication with username and password
            session.auth = (
                endpoint_config.api_username, 
                endpoint_config.api_password.get_secret_value()
            )
            endpoint = endpoint_config.api_url
            
            msg = f"Remote data provider for token {token} at {endpoint}"
            logline = lu.LOG_FMT.format(
                id=lu.get_session_id(context.state), message=msg
            )
            logger.info(logline)
            remote_response = None
            for attemp in range(0,endpoint_config.api_retries):
                try:
                    remote_response = session.post(endpoint, timeout=endpoint_config.api_timeout)
                    remote_response.raise_for_status()  # Handle HTTP errors
                    new_response = remote_response.json()
                    logline = lu.LOG_FMT.format(
                        id=lu.get_session_id(context.state), message=msg
                    )
                    logger.info(logline)
                    wrap_claim_name = endpoint_config.wrap_claim_name
                    if wrap_claim_name:
                        local_args["response_args"].update({wrap_claim_name: new_response})
                    else:
                        local_args["response_args"].update(new_response)
                    break
                except (Exception, Timeout) as e:
                    msg = f"Remote data provider error: {e}"
                    logline = lu.LOG_FMT.format(
                        id=lu.get_session_id(context.state), message=msg
                    )
                    logger.error(logline)
                    continue
            if not endpoint_config.ignore_api_error and remote_response and remote_response.status_code != 200:
                status = remote_response.status_code
                local_args.update({"error": "api error", "error_description": f"The API call was not succesfull (status code: {status})" })           
                return local_args

        return local_args

