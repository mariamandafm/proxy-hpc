import copy
import json
import secrets
import string
from base64 import urlsafe_b64encode
from collections import Counter
from unittest.mock import MagicMock, Mock, mock_open, patch
from urllib.parse import parse_qs, parse_qsl, urlparse

import pytest
import requests
import requests_mock
import responses
import tests.util
from bs4 import BeautifulSoup
from idpyoidc.message.oauth2 import (
    AuthorizationRequest,
    CCAccessTokenRequest,
    TokenExchangeRequest,
    TokenIntrospectionRequest,
    TokenIntrospectionResponse,
    TokenRevocationErrorResponse,
    TokenRevocationRequest,
    TokenRevocationResponse,
)
from idpyoidc.message.oidc import (
    AccessTokenRequest,
    AccessTokenResponse,
    AuthorizationErrorResponse,
    AuthorizationResponse,
    Claims,
    ClaimsRequest,
    ClientRegistrationErrorResponse,
    OpenIDSchema,
    ProviderConfigurationResponse,
    RefreshAccessTokenRequest,
    RegistrationRequest,
    RegistrationResponse,
    TokenErrorResponse,
)
from idpyoidc.alg_info import get_signing_algs
from idpyoidc.server.client_authn import ClientAuthenticationError
from idpyoidc.server.oauth2.add_on.pkce import CC_METHOD
from idpyoidc.server.scopes import SCOPE2CLAIMS
from idpyoidc.server.session.claims import available_claims
from idpyoidc.server.session.token import AccessToken
from idpyoidc.time_util import utc_time_sans_frac
from jwkest.jwk import load_jwks
from requests.exceptions import Timeout
from satosa.attribute_mapping import AttributeMapper
from satosa.exception import SATOSAAuthenticationError, SATOSAConfigurationError
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import BadRequest, Unauthorized
from satosa_oidc_frontend import AttributeAuth
from satosa_oidc_frontend.frontend import KEY_REQUESTER_METADATA, ClientDBHashedSecrets, OpenIDConnectFrontend
from tests.users import OIDC_USERS

BASECH = string.ascii_letters + string.digits + "-._~"

INTERNAL_ATTRIBUTES = {
    "attributes": {
        "mail": {"saml": ["email"], "openid": ["email"]},
        "email_verified": {"openid": ["email_verified"]},
        "eduPersonTargetedID": {"saml": ["eduPersonTargetedID"], "openid": ["sub"]},
        "givenname": {"saml": ["givenName"], "openid": ["given_name"]},
    }
}
BASE_URL = "https://op.example.com"
CLIENT_ID = "client1"
CLIENT_SECRET = "client_secret"
EXTRA_CLAIMS = {
    "eduPersonScopedAffiliation": {
        "saml": ["eduPersonScopedAffiliation"],
        "openid": ["eduperson_scoped_affiliation"],
    },
    "eduPersonPrincipalName": {
        "saml": ["eduPersonPrincipalName"],
        "openid": ["eduperson_principal_name"],
    },
}
EXTRA_SCOPES = {
    **SCOPE2CLAIMS,
    "eduperson": ["eduperson_scoped_affiliation", "eduperson_principal_name"],
}
JWKS = [{"type": "RSA", "use": ["sig"]}, {"type": "EC", "crv": "P-256", "use": ["sig"]}]
OIDC_USERS["testuser1"]["email_verified"] = True
response_types_supported = [
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "token id_token",
    "code id_token token",
]


def unreserved(size=64):
    return "".join(secrets.choice(BASECH) for _ in range(size))


def _code_challenge():
    """
    PKCE aka RFC 7636
    """
    # code_verifier: string of length cv_len
    code_verifier = unreserved(64)

    _method = "S256"

    # Pick hash method
    _hash_method = CC_METHOD[_method]
    # base64 encode the hash value
    code_challenge = _hash_method(code_verifier)

    return {
        "code_challenge": code_challenge,
        "code_challenge_method": _method,
        "code_verifier": code_verifier,
    }


def create_frontend(frontend_config, internal_attributes=INTERNAL_ATTRIBUTES):
    instance = OpenIDConnectFrontend(
        lambda ctx, req: None,
        internal_attributes,
        frontend_config,
        BASE_URL,
        "oidc_frontend",
    )
    instance.register_endpoints(["foo_backend"])
    return instance


def create_frontend_extra_scopes(frontend_config_extra_scopes):
    internal_attributes = copy.deepcopy(INTERNAL_ATTRIBUTES)
    internal_attributes["attributes"].update(EXTRA_CLAIMS)
    instance = OpenIDConnectFrontend(
        lambda ctx, req: None,
        internal_attributes,
        frontend_config_extra_scopes,
        BASE_URL,
        "oidc_frontend_extra_scopes",
    )
    instance.register_endpoints(["foo_backend"])
    return instance


@pytest.fixture
def insert_client():
    def _insert_client(
        frontend,
        redirect_uri,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        extra_metadata=None,
    ):
        if client_secret and frontend.config.get(
            "client_db_enable_secret_hashing_on_import"
        ):
            client_secret = frontend.hash_client_secret(client_secret)

        frontend.client_db[client_id] = {
            "response_types_supported": response_types_supported,
            "redirect_uris": [(redirect_uri, "")],
            "client_secret": client_secret,
            "allowed_scopes": ["openid", "email", "offline_access", "eduperson"],
            **(extra_metadata or {}),
        }

    return _insert_client


def create_auth(client_id, client_secret):
    credentials = "{}:{}".format(client_id, client_secret)
    basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
    return "Basic {}".format(basic_auth)


def insert_userinfo(frontend, user_id):
    user_attributes = frontend.converter.to_internal("saml", OIDC_USERS["testuser1"])
    frontend.user_db[user_id] = frontend.converter.from_internal(
        "openid", user_attributes
    )


def setup_for_authn_response(context, frontend, authn_req):
    context.state[frontend.name] = {"oidc_request": authn_req}
    context.request = authn_req
    frontend._handle_authn_request(context)

    PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
    auth_info = AuthenticationInformation(
        PASSWORD, "2015-09-30T12:21:37Z", "unittest_idp.xml"
    )
    internal_response = InternalData(auth_info=auth_info)
    internal_response.attributes = AttributeMapper(
        frontend.internal_attributes
    ).to_internal("saml", OIDC_USERS["testuser1"])
    internal_response.subject_id = "fasdgasdgasdvasdtfasdgqwertqwerjghkfiosdrgsdf"
    internal_response.attributes["email_verified"] = [
        OIDC_USERS["testuser1"]["email_verified"]
    ]
    context.request = None

    return internal_response

def setup_for_authn_response_acr(context, frontend, authn_req):
    context.state[frontend.name] = {"oidc_request": authn_req}
    context.request = authn_req
    http_resp = frontend._handle_authn_request(context)
    if hasattr(http_resp, "message"):
      resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).query)
      if "error" in resp:
        return resp
    auth_info = AuthenticationInformation(
        auth_class_ref="urn:oasis:names:tc:SAML:2.0:ac:classes:OTP",
        auth_time="2025-03-10T12:00:00Z",
        issuer="test-idp",
    )
    internal_response = InternalData(auth_info=auth_info)
    internal_response.attributes = AttributeMapper(
        frontend.internal_attributes
    ).to_internal("saml", OIDC_USERS["testuser1"])
    context.request = None

    return internal_response


def test_import_hooks_not_list(frontend_config):
    """
    Test that import hooks raises if not provided with list
    """
    frontend_config["introspection_post_process_hooks"] = {
        "function": "tests.util.mock"
    }

    with pytest.raises(SATOSAConfigurationError) as e:
        create_frontend(frontend_config)
    assert e.value.args[0] == "introspection_post_process_hooks must be a list"


def test_import_hooks_bad_class_path(frontend_config):
    """
    Test that import hooks raises if the provided path is not correct
    """
    module_path = "tests.util"
    fun = "mock123"
    frontend_config["introspection_post_process_hooks"] = [
        {"class": ".".join([module_path, fun])}
    ]

    with pytest.raises(SATOSAConfigurationError) as e:
        create_frontend(frontend_config)
    assert e.value.args[0] == f"module '{module_path}' has no attribute '{fun}'"


def test_import_hooks_not_class(monkeypatch, frontend_config):
    """
    Test that import hooks raises if the provided function is not a
    callable
    """
    fun = 1
    cls_path = "tests.util.mock"
    monkeypatch.setattr(tests.util, "mock", fun)
    frontend_config["introspection_post_process_hooks"] = [{"class": cls_path}]

    with pytest.raises(SATOSAConfigurationError) as e:
        create_frontend(frontend_config)
    assert e.value.args[0] == f"'{cls_path}' is not a class"


def test_import_hooks_no_attribute(monkeypatch, frontend_config):
    """
    Test that import hooks raises if the provided function is not a
    callable
    """

    class Mock:
        pass

    cls_path = "tests.util.mock"
    fun = "fun"
    monkeypatch.setattr(tests.util, "mock", Mock)
    frontend_config["introspection_post_process_hooks"] = [
        {"class": cls_path, "function": fun}
    ]

    with pytest.raises(SATOSAConfigurationError) as e:
        create_frontend(frontend_config)
    assert (
        e.value.args[0] == f"The provided class '{cls_path}' has no attribute '{fun}'"
    )


def test_import_hooks_cls_not_callable_fun(monkeypatch, frontend_config):
    """
    Test that import hooks raises if the provided class function is not a
    callable
    """

    class Mock:
        fun = 1

    cls_path = "tests.util.mock"
    fun = "fun"
    monkeypatch.setattr(tests.util, "mock", Mock)
    frontend_config["introspection_post_process_hooks"] = [
        {"class": cls_path, "function": fun}
    ]

    with pytest.raises(SATOSAConfigurationError) as e:
        create_frontend(frontend_config)
    assert (
        e.value.args[0]
        == f"The provided function '{fun}' for class '{cls_path}' is not "
        "callable"
    )


def test_import_hooks_cls_not_callable(monkeypatch, frontend_config):
    """
    Test that import hooks raises if the provided class is not a
    callable
    """

    class Mock:
        pass

    cls_path = "tests.util.mock"
    monkeypatch.setattr(tests.util, "mock", Mock)
    frontend_config["introspection_post_process_hooks"] = [{"class": cls_path}]

    with pytest.raises(SATOSAConfigurationError) as e:
        create_frontend(frontend_config)
    assert e.value.args[0] == f"The provided class '{cls_path}' is not callable"


def test_import_hooks_cls_init(monkeypatch, frontend_config):
    """
    Test that the provided kwargs are used to initialize the class object
    """

    class Mock:
        args = None
        kwargs = None

        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def __call__(self):
            pass

    cls_path = "tests.util.mock"
    kwargs = dict(a=1, b=2)
    monkeypatch.setattr(tests.util, "mock", Mock)
    frontend_config["introspection_post_process_hooks"] = [
        {"class": cls_path, "kwargs": kwargs}
    ]

    frontend = create_frontend(frontend_config)

    assert frontend.introspection_post_process_hooks[0].kwargs == kwargs


def test_import_hooks_cls(monkeypatch, frontend_config):
    """
    Test that if no function is provided the class is returned
    """
    mock = MagicMock()

    class Mock:
        args = None
        kwargs = None

        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def __call__(self):
            return mock

    cls_path = "tests.util.mock"
    monkeypatch.setattr(tests.util, "mock", Mock)
    frontend_config["introspection_post_process_hooks"] = [{"class": cls_path}]

    frontend = create_frontend(frontend_config)

    assert len(frontend.introspection_post_process_hooks) == 1
    assert isinstance(frontend.introspection_post_process_hooks[0], Mock)
    assert frontend.introspection_post_process_hooks[0]() == mock


def test_import_hooks_cls_fun(monkeypatch, frontend_config):
    """
    Test that the provided function is returned
    """
    mock = MagicMock()

    class Mock:
        args = None
        kwargs = None

        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        def fun(self):
            return mock

    cls_path = "tests.util.mock"
    monkeypatch.setattr(tests.util, "mock", Mock)
    frontend_config["introspection_post_process_hooks"] = [
        {"class": cls_path, "function": "fun"}
    ]

    frontend = create_frontend(frontend_config)

    assert len(frontend.introspection_post_process_hooks) == 1
    assert frontend.introspection_post_process_hooks[0]() == mock


class TestOpenIDConnectFrontend(object):
    @pytest.fixture
    def frontend(self, frontend_config):
        return create_frontend(frontend_config)

    @pytest.fixture
    def frontend_extra_scopes(self, frontend_config_extra_scopes):
        return create_frontend_extra_scopes(frontend_config_extra_scopes)

    def create_access_token(self, context, frontend, authn_req):
        authn_req["response_type"] = "token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        resp = frontend.handle_authn_response(context, internal_response)
        # Flush client_db
        frontend.endpoint_context.cdb = {}
        return parse_qs(urlparse(resp.message).fragment)["access_token"][0]

    def test_default_sub_func(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test that the sub_func defaults to the identity function
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        id_token = AuthorizationResponse().from_jwt(
            resp["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        attributes = frontend.converter.from_internal(
            "openid", internal_response.attributes
        )
        sub = attributes.get("sub", [None])[0]

        assert id_token["sub"] == sub

    def test_custom_sub_func(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that the sub_func parameter is used
        """
        sub_func = Mock()
        sub_func.return_value = "1"
        frontend_config["sub_func"] = dict(public={"function": sub_func})

        frontend = create_frontend(frontend_config)

        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        id_token = AuthorizationResponse().from_jwt(
            resp["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert id_token["sub"] == "1"

    def test_handle_authn_response(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test that the frontend handles the authentication response properly.
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        assert resp["state"] == authn_req["state"]

        id_token = AuthorizationResponse().from_jwt(
            resp["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert id_token["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert id_token["nonce"] == authn_req["nonce"]
        assert id_token["aud"] == [authn_req["client_id"]]
        assert "sub" in id_token
        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert frontend.name not in context.state

        with pytest.raises(Exception):
            AuthorizationResponse().from_jwt(
                resp["access_token"], frontend.endpoint_context.keyjar, sender=""
            ).verify()

    def test_handle_authn_response_form_post(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the frontend handles the authentication response properly.
        """
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_mode"] = "form_post"
        authn_req["response_type"] = "code id_token token"

        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)

        parsed_html = BeautifulSoup(http_resp.message, features="html.parser")

        form = parsed_html.find("form")
        inputs = form.findAll("input")
        request_params = {
            inp.attrs["name"]: inp.attrs["value"]
            for inp in inputs
            if "name" in inp.attrs
        }

        assert request_params["state"] == authn_req["state"]
        id_token = AuthorizationResponse().from_jwt(
            request_params["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert id_token["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert id_token["nonce"] == authn_req["nonce"]
        assert id_token["aud"] == [authn_req["client_id"]]
        assert "sub" in id_token
        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert frontend.name not in context.state
        assert (
            AuthorizationResponse()
            .from_jwt(
                request_params["access_token"],
                frontend.endpoint_context.keyjar,
                sender="",
            )
            .verify()
        )

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=request_params["code"]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["id_token"]

    def test_handle_authn_response_no_sub(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that the frontend handles the authentication response properly.
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        internal_response.attributes.pop("eduPersonTargetedID")
        http_resp = frontend.handle_authn_response(context, internal_response)

        assert http_resp.message.startswith(authn_req["redirect_uri"])

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).query)
        assert resp.to_dict() == {
            "error": "access_denied",
            "error_description": "No sub retrieved for user",
            "state": authn_req["state"],
        }

    def test_handle_authn_response_jwt(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the frontend handles the authentication response properly.
        """
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        assert resp["state"] == authn_req["state"]

        id_token = AuthorizationResponse().from_jwt(
            resp["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert id_token["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert id_token["nonce"] == authn_req["nonce"]
        assert id_token["aud"] == [authn_req["client_id"]]
        assert "sub" in id_token
        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert frontend.name not in context.state

        assert (
            AuthorizationResponse()
            .from_jwt(resp["access_token"], frontend.endpoint_context.keyjar, sender="")
            .verify()
        )

    def test_handle_authn_request(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test that the frontend handles the authentication request properly.
        """
        mock_callback = Mock()
        frontend.auth_req_callback_func = mock_callback
        client_name = "test client"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"client_name": client_name},
        )

        context.request = authn_req
        frontend.handle_authn_request(context)

        assert mock_callback.call_count == 1
        context, internal_req = mock_callback.call_args[0]
        assert internal_req.requester == authn_req["client_id"]
        assert internal_req.requester_name == [{"lang": "en", "text": client_name}]
        assert internal_req.subject_type == "pairwise"
        assert set(internal_req.attributes) == {"mail", "eduPersonTargetedID"}

    def test_handle_acr_authn_request(self, context, frontend, authn_req, insert_client):
        """
        Test that the frontend handles the acr_values at authentication request properly.
        """
        mock_callback = Mock()
        frontend.auth_req_callback_func = mock_callback
        client_name = "test client"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"client_name": client_name},
        )
        authn_req["acr_values"] = "urn:mace:incommon:iap:bronze"
        context.request = authn_req
        frontend.handle_authn_request(context)

        assert mock_callback.call_count == 1
        context, internal_req = mock_callback.call_args[0]
        assert internal_req.requester == authn_req["client_id"]
        assert internal_req.requester_name == [{"lang": "en", "text": client_name}]
        assert internal_req.subject_type == "pairwise"
        assert set(internal_req.attributes) == {"mail", "eduPersonTargetedID"}

    @pytest.mark.parametrize("acr_values", [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:OTP", 
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport urn:oasis:names:tc:SAML:2.0:ac:classes:OTP"
    ])
    def test_handle_acr_authn_response_jwt(self, context, frontend_config, authn_req, acr_values, insert_client):
        """
        Test that the frontend handles acr_values request properly, including single and multiple acr_values cases.
        """
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        authn_req["acr_values"] = acr_values
        
        internal_response = setup_for_authn_response_acr(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])
        
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        assert resp["state"] == authn_req["state"]
        
        id_token = AuthorizationResponse().from_jwt(
            resp["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert id_token["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert id_token["nonce"] == authn_req["nonce"]
        assert id_token["aud"] == [authn_req["client_id"]]
        
        # Ensure one of the acr values is included in the response
        if " " in acr_values:
            assert id_token["acr"] in acr_values.split(" ")
        else:
            assert id_token["acr"] == acr_values
        
        assert "auth_time" in id_token
        assert "sub" in id_token
        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert frontend.name not in context.state
        
        assert (
            AuthorizationResponse()
            .from_jwt(resp["access_token"], frontend.endpoint_context.keyjar, sender="")
            .verify()
        )

    def test_handle_both_acr_values_and_claims_fail(self, context, frontend_config, authn_req, insert_client):
        """
        Test that the frontend returns an error when the request contains both acr_values and acr in claims.
        """
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        authn_req["acr_values"] = "urn:oasis:names:tc:SAML:2.0:ac:classes:OTP"
        authn_req["claims"] = {"id_token": {"acr": {"values": "urn:oasis:names:tc:SAML:2.0:ac:classes:OTP"}}}
        internal_response = setup_for_authn_response_acr(context, frontend, authn_req)
        
        assert internal_response.to_dict() == {
            "error": "access_denied",
            "error_description": "The request had both acr_values and the claims param for acr value",
            "state": authn_req["state"],
        }
        assert "error" in internal_response
        
    def test_handle_essential_true_acr_values_fail(self, context, frontend_config, authn_req, insert_client):
        """
        Test that the frontend returns an error when the essential is true and acr value not in the response.
        """
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        authn_req["claims"] = {"id_token": {"acr": {"essential": True,"values": "urn:oasis:names:tc:SAML:2.0:ac:classes:OTP2"}}}
        internal_response = setup_for_authn_response_acr(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).query)
        assert resp.to_dict() == {
            "error": "access_denied",
            "error_description": "Requested ACR not satisfied",
            "state": authn_req["state"],
        }
        
    def test_handle_client_config_acr_authn_response_jwt(self, context, frontend_config, authn_req, insert_client):
        """
        Test that the frontend handles the acr at the client configuration properly and overrides any acr value
        that is in the request.
        """
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(frontend, 
                      authn_req["redirect_uri"], 
                      extra_metadata = {"requested_acrs": ["urn:oasis:names:tc:SAML:2.0:ac:classes:OTP"]}
                    )
        authn_req["response_type"] = "code id_token token"
        # Put at the request another acr value than at requested_acrs
        authn_req["acr_values"] = "urn:oasis:names:tc:SAML:2.0:ac:classes:OTP2"
        internal_response = setup_for_authn_response_acr(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        assert http_resp.message.startswith(authn_req["redirect_uri"])

        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        assert resp["state"] == authn_req["state"]

        id_token = AuthorizationResponse().from_jwt(
            resp["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert id_token["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert id_token["nonce"] == authn_req["nonce"]
        assert id_token["aud"] == [authn_req["client_id"]]
        assert id_token["acr"] in frontend.endpoint_context.cdb[CLIENT_ID]["requested_acrs"]
        assert "auth_time" in id_token
        assert "sub" in id_token
        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert frontend.name not in context.state

        assert (
            AuthorizationResponse()
            .from_jwt(resp["access_token"], frontend.endpoint_context.keyjar, sender="")
            .verify()
        )

    def test_handle_authn_request_unknown_client(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that the frontend returns a correct error response if the
        client_id is unknown.
        """
        client_name = "test client"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"client_name": client_name},
        )

        authn_req["client_id"] = "UNKNWOWN"
        context.request = authn_req
        resp = frontend.handle_authn_request(context)

        assert isinstance(resp, BadRequest)
        assert json.loads(resp.message) == {
            "error": "invalid_client",
            "error_description": "Unknown Client ID",
        }

    def test_handle_authn_request_no_client(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that the frontend returns a correct error response when no
        client_id is provided.
        """
        client_name = "test client"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"client_name": client_name},
        )

        authn_req.pop("client_id")
        context.request = authn_req
        resp = frontend.handle_authn_request(context)

        assert isinstance(resp, BadRequest)
        assert json.loads(resp.message) == {
            "error": "invalid_request",
            "error_description": "Missing required attribute 'client_id'",
        }

    def test_handle_authn_request_wrong_redirect_uri(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that the frontend returns a correct error response if the
        redirect_uri does not match the registered one.
        """
        client_name = "test client"
        insert_client(
            frontend,
            authn_req["redirect_uri"] + "a",
            extra_metadata={"client_name": client_name},
        )

        context.request = authn_req
        resp = frontend.handle_authn_request(context)

        assert isinstance(resp, BadRequest)
        assert json.loads(resp.message) == {
            "error": "invalid_request",
            "error_description": "RedirectURIError:Doesn't match any registered uris",
            "state": "my_state",
        }

    def test_handle_registration(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test that a client can register successfully with the default authentication
        method, Bearer header.
        """
        insert_client(frontend, authn_req["redirect_uri"])
        token = self.create_access_token(context, frontend, authn_req)
        context.request_authorization = "Bearer {}".format(token)

        redirect_uri = "https://newclient.example.com"
        registration_request = RegistrationRequest(
            redirect_uris=[redirect_uri],
            response_types=["id_token"],
            client_id=authn_req["client_id"],
        )
        context.request = registration_request.to_dict()
        registration_response = frontend.handle_registration(context)
        assert registration_response.status == "201 Created"

        reg_resp = RegistrationResponse().deserialize(
            registration_response.message, "json"
        )
        assert "client_id" in reg_resp
        assert reg_resp["redirect_uris"] == [redirect_uri]
        assert reg_resp["response_types"] == ["id_token"]

    @pytest.mark.parametrize("has_attributes", [True, False])
    def test_handle_authenticated_attribute_registration(
        self,
        context,
        frontend_config_extra_scopes,
        authn_req,
        attribute_auth_config,
        has_attributes,
        insert_client,
    ):
        """
        Test that a client can register successfully only with a token containing
        the attributes required by AttributeAuth.

        TODO: Move this test under TestAttributeAuth
        """
        frontend_config_extra_scopes.update(attribute_auth_config)

        internal_attributes = copy.deepcopy(INTERNAL_ATTRIBUTES)
        if has_attributes:
            internal_attributes["attributes"].update(EXTRA_CLAIMS)
        frontend = create_frontend(
            frontend_config_extra_scopes, internal_attributes=internal_attributes
        )

        insert_client(frontend, authn_req["redirect_uri"])

        token = self.create_access_token(context, frontend, authn_req)
        context.request_authorization = "Bearer {}".format(token)

        redirect_uri = "https://newclient.example.com"
        registration_request = RegistrationRequest(
            redirect_uris=[redirect_uri], response_types=["id_token"]
        )
        context.request = registration_request.to_dict()
        registration_response = frontend.handle_registration(context)

        if not has_attributes:
            assert registration_response.status == "400 Bad Request"
            return

        assert registration_response.status == "201 Created"

        reg_resp = RegistrationResponse().deserialize(
            registration_response.message, "json"
        )
        if has_attributes:
            assert "client_id" in reg_resp
            assert reg_resp["redirect_uris"] == [redirect_uri]
            assert reg_resp["response_types"] == ["id_token"]

    def test_handle_introspection_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        """Test that a client can use introspection on a token."""
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        introspection_request = TokenIntrospectionRequest(
            token="INVALIDINVALIDINVALID", client_id=CLIENT_ID
        )
        context.request = introspection_request.to_dict()

        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )
        # This will be fixed by the new oidcendpoint version
        assert "active" in intro_resp
        assert intro_resp["active"] is False

    def test_handle_introspection_success(
        self, context, frontend_config, authn_req, insert_client
    ):
        user_id = "test_user"
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        attributes = frontend.converter.from_internal(
            "openid", internal_response.attributes
        )
        sub = attributes.get("sub", [None])[0]

        assert intro_resp["active"] is True
        assert intro_resp["client_id"] == authn_req["client_id"]
        assert intro_resp["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert intro_resp["sub"] == sub
        assert intro_resp["token_type"] == "Bearer"
        assert intro_resp["scope"] == authn_req["scope"]
        assert "iat" in intro_resp
        assert "exp" in intro_resp

    def test_handle_introspection_expired_token(
        self, context, frontend_config, authn_req, monkeypatch, insert_client
    ):
        lifetime = 100
        frontend_config["access_token_lifetime"] = lifetime
        frontend_config["jwt_access_token"] = True

        user_id = "test_user"
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()

        def mock():
            return utc_time_sans_frac() + lifetime + 1

        monkeypatch.setattr("idpyoidc.server.token.utc_time_sans_frac", mock)

        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert intro_resp.to_dict() == {"active": False}

    @pytest.mark.parametrize("enabled_intro_claims", [True, False])
    def test_introspection_claims_per_client(
        self, context, frontend_config, authn_req, enabled_intro_claims, insert_client
    ):
        """
        Test that the introspection response includes the configured claims.
        """
        frontend_config["enable_introspection_claims_per_client"] = enabled_intro_claims
        frontend = create_frontend(frontend_config)
        client_claims = {
            "add_claims": {"always": {"introspection": {"email_verified": None}}}
        }
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=client_claims)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert intro_resp["active"] is True
        assert ("email_verified" in intro_resp) is enabled_intro_claims
        if enabled_intro_claims:
            assert (
                intro_resp["email_verified"]
                == OIDC_USERS["testuser1"]["email_verified"]
            )

    def test_handle_introspection_code(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Introspection must return active=True only if an access token or
        an refresh token is provided

        """
        user_id = "test_user"
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        introspection_request = TokenIntrospectionRequest(token=code)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )
        assert "active" in intro_resp
        assert intro_resp["active"] is False

    def test_handle_introspection_refresh(
        self, context, frontend_config, authn_req, insert_client
    ):
        user_id = "test_user"
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        refresh_token = parsed["refresh_token"]

        introspection_request = TokenIntrospectionRequest(token=refresh_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )
        assert "active" in intro_resp
        assert intro_resp["active"] is True

    def test_handle_introspection_id_token(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Introspection must return active=True only if an access token or
        an refresh token is provided
        """
        user_id = "test_user"
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = parsed["id_token"]

        introspection_request = TokenIntrospectionRequest(token=id_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )
        assert "active" in intro_resp
        assert intro_resp["active"] is False

    def test_handle_authn_request_with_extra_scopes(
        self, context, frontend_extra_scopes, authn_req_extra_scopes, insert_client
    ):
        """
        Test that the frontend with extra scopes handles the authentication
        request properly.
        """
        client_name = "test client"
        insert_client(
            frontend_extra_scopes,
            authn_req_extra_scopes["redirect_uri"],
            extra_metadata={"client_name": client_name},
        )

        context.request = authn_req_extra_scopes
        frontend_extra_scopes.handle_authn_request(context)
        internal_req = frontend_extra_scopes._handle_authn_request(context)
        assert internal_req.requester == authn_req_extra_scopes["client_id"]
        assert internal_req.requester_name == [{"lang": "en", "text": client_name}]
        assert internal_req.subject_type == "pairwise"
        assert set(internal_req.attributes) == {
            "eduPersonPrincipalName",
            "eduPersonScopedAffiliation",
            "eduPersonTargetedID",
            "email_verified",
            "mail",
        }

    def test_get_approved_attributes(self, frontend):
        """
        Test the `_get_approved_attributes` function, it should only return
        claims that map to both the supported scopes and to the requested
        scopes.
        """
        claims_req = ClaimsRequest(
            id_token=Claims(name=None), userinfo=Claims(userinfo_claim=None)
        )
        req = AuthorizationRequest(scope="openid email", claims=claims_req)

        result = frontend._get_approved_attributes(req)
        assert Counter(result) == Counter(["sub", "email", "email_verified"])

    def test_get_approved_attributes_unsupported_scope(self, frontend):
        """
        Test the `_get_approved_attributes` function, it should only return
        claims that map to both the supported scopes and to the requested
        scopes, the unsupported scope must be ignored.
        """
        claims_req = ClaimsRequest(
            id_token=Claims(email=None), userinfo=Claims(userinfo_claim=None)
        )
        req = AuthorizationRequest(scope="openid eduperson", claims=claims_req)
        result = frontend._get_approved_attributes(req)
        assert Counter(result) == Counter(["sub", "email"])

    def test_get_approved_attributes_extra_scopes(self, frontend_extra_scopes):
        """
        Test that the extra scopes are taken into account in
        `_get_approved_attributes`.
        """
        claims_req = ClaimsRequest(
            id_token=Claims(email=None), userinfo=Claims(userinfo_claim=None)
        )
        req = AuthorizationRequest(scope="openid eduperson", claims=claims_req)

        result = frontend_extra_scopes._get_approved_attributes(req)
        assert Counter(result) == Counter(
            ["sub", "email", "eduperson_scoped_affiliation", "eduperson_principal_name"]
        )

    @pytest.mark.xfail(
        reason="SATOSAAuthenticationError does not propagate the provided "
        "error_description (SATOSA core limitation)."
    )
    def test_handle_backend_error(self, context, frontend):
        """
        Test that errors received on the backend are handled properly.

        This test fails because SATOSAAuthenticationError does not use the
        provided error_description.
        """
        redirect_uri = "https://client.example.com"
        areq = AuthorizationRequest(
            client_id=CLIENT_ID,
            scope="openid",
            response_type="id_token",
            redirect_uri=redirect_uri,
        )
        context.state[frontend.name] = {"oidc_request": areq}

        # fake an error
        message = "test error"
        error = SATOSAAuthenticationError(context.state, message)
        resp = frontend.handle_backend_error(error)

        assert resp.message.startswith(redirect_uri)
        error_response = AuthorizationErrorResponse().deserialize(
            urlparse(resp.message).fragment
        )
        assert error_response["error"] == "access_denied"
        assert error_response["error_description"] == message

    def test_clients_json(self, context, frontend_config, authn_req):
        """
        Test that a JSON clients file can be imported and is respected.
        """
        # The frontend only reads client_json_path when import is enabled
        # (frontend.py: client_db_enable_import gate).
        if not frontend_config.get("client_db_enable_import"):
            pytest.skip("client import is disabled in this config")
        clients_json = {
            CLIENT_ID: {
                "redirect_uris": [[authn_req["redirect_uri"], ""]],
                "response_types": ["code"],
                "client_secret": CLIENT_SECRET,
            }
        }
        frontend_config["client_json_path"] = "/tmp/mocked"
        with patch(
            "builtins.open", mock_open(read_data=json.dumps(clients_json))
        ) as mock_file:
            frontend = create_frontend(frontend_config)
            mock_file.assert_called_with("/tmp/mocked")

        test_client = clients_json[CLIENT_ID]
        assert frontend.endpoint_context.cdb[CLIENT_ID] == test_client

        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "access_token" in parsed
        assert "id_token" in parsed

    @pytest.mark.parametrize("overwrite_clients_in_db", [True, False])
    def test_clients_json_overwrite(
        self,
        context,
        frontend_config,
        authn_req,
        overwrite_clients_in_db,
        insert_client,
    ):
        """
        Test that clients in db are/aren't overwritten based on the JSON clients file.
        """
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])

        new_redirect_uri = ["https://newredirect.example.com", ""]

        clients_json = {
            CLIENT_ID: {
                "redirect_uris": [new_redirect_uri],
                "response_types": ["code"],
                "client_secret": CLIENT_SECRET,
            }
        }

        frontend.config["client_json_path"] = "/tmp/mocked"
        frontend.config["overwrite_clients_in_db"] = overwrite_clients_in_db
        with patch(
            "builtins.open", mock_open(read_data=json.dumps(clients_json))
        ) as mock_file:
            frontend.import_clients()
            mock_file.assert_called_with("/tmp/mocked")

        existing_client = frontend.client_db[CLIENT_ID]
        assert (
            new_redirect_uri in existing_client["redirect_uris"]
        ) is overwrite_clients_in_db

    def test_client_authn_methods_public(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = ["public"]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code, client_id=CLIENT_ID
        ).to_dict()

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["id_token"]

    def test_client_authn_methods_public_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = ["client_secret_basic"]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code, client_id=CLIENT_ID
        ).to_dict()

        response = frontend.handle_token(context)

        assert isinstance(response, BadRequest)
        assert json.loads(response.message) == {
            "error": "invalid_client",
            "error_description": "Authorization failed",
        }

    def test_client_authn_methods_public_per_client_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = ["client_secret_basic", "public"]
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata=dict(client_authn_method=["client_secret_basic"]),
        )

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)

        assert isinstance(http_resp, BadRequest)
        assert json.loads(http_resp.message) == {
            "error": "invalid_client",
            "error_description": "Authorization failed",
        }

    def test_client_authn_methods_client_secret_basic(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = ["client_secret_basic"]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["id_token"]

    def test_client_authn_methods_client_secret_basic_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = ["client_secret_post"]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        assert isinstance(response, BadRequest)
        assert json.loads(response.message) == {
            "error": "invalid_client",
            "error_description": "Authorization failed",
        }

    def test_client_authn_methods_client_secret_basic_per_client_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = ["client_secret_basic", "public"]
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata=dict(client_authn_method=["client_secret_post"]),
        )

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)

        assert isinstance(http_resp, BadRequest)
        assert json.loads(http_resp.message) == {
            "error": "invalid_client",
            "error_description": "Authorization failed",
        }

    def test_client_authn_methods_client_secret_post(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = ["client_secret_post"]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
        ).to_dict()

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["id_token"]

    def test_client_authn_methods_client_secret_post_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = ["client_secret_basic"]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
        ).to_dict()

        response = frontend.handle_token(context)

        assert isinstance(response, BadRequest)
        assert json.loads(response.message) == {
            "error": "invalid_client",
            "error_description": "Authorization failed",
        }

    def test_client_authn_methods_client_secret_post_per_client_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["client_authn_method"] = [
            "client_secret_basic",
            "client_secret_post",
        ]
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata=dict(client_authn_method=["client_secret_post"]),
        )

        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        response = frontend.handle_authn_response(context, internal_response)

        assert isinstance(response, BadRequest)
        assert json.loads(response.message) == {
            "error": "invalid_client",
            "error_description": "Authorization failed",
        }

    def test_register_client(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test that the frontend handles client registration properly.
        """
        insert_client(frontend, authn_req["redirect_uri"])
        token = self.create_access_token(context, frontend, authn_req)
        context.request_authorization = "Bearer {}".format(token)

        redirect_uri = "https://newclient.example.com"
        registration_request = RegistrationRequest(
            redirect_uris=[redirect_uri],
            response_types=["id_token"],
            client_id=CLIENT_ID,
        )
        context.request = registration_request.to_dict()
        registration_response = frontend.handle_registration(context)
        assert registration_response.status == "201 Created"

        reg_resp = RegistrationResponse().deserialize(
            registration_response.message, "json"
        )
        assert "client_id" in reg_resp
        assert reg_resp["redirect_uris"] == [redirect_uri]
        assert reg_resp["response_types"] == ["id_token"]

    def test_register_client_many_resp_types(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that a client can register if his response type is in the
        supported response types.
        """
        insert_client(frontend, authn_req["redirect_uri"])
        token = self.create_access_token(context, frontend, authn_req)
        context.request_authorization = "Bearer {}".format(token)

        redirect_uri = "https://newclient.example.com"
        response_types = ["code id_token token", "id_token"]
        registration_request = RegistrationRequest(
            redirect_uris=[redirect_uri],
            response_types=response_types,
            client_id=CLIENT_ID,
        )
        context.request = registration_request.to_dict()
        registration_response = frontend.handle_registration(context)
        assert registration_response.status == "201 Created"

        reg_resp = RegistrationResponse().deserialize(
            registration_response.message, "json"
        )
        assert "client_id" in reg_resp
        assert reg_resp["redirect_uris"] == [redirect_uri]
        assert set(reg_resp["response_types"]) == set(response_types)

    def test_register_client_with_wrong_response_type(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that when a client tries to register with an unsupported
        response type an error is returned.
        """
        frontend_config["response_types_supported"] = ["code", "token", "id_token"]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        token = self.create_access_token(context, frontend, authn_req)
        context.request_authorization = "Bearer {}".format(token)

        redirect_uri = "https://newclient.example.com"
        registration_request = RegistrationRequest(
            redirect_uris=[redirect_uri],
            response_types=["id_token token"],
            client_id=CLIENT_ID,
        )
        context.request = registration_request.to_dict()
        registration_response = frontend.handle_registration(context)
        assert registration_response.status == "400 Bad Request"
        error_response = ClientRegistrationErrorResponse().deserialize(
            registration_response.message, "json"
        )
        assert error_response["error"] == "invalid_request"
        assert "response_type" in error_response["error_description"]

    def test_provider_info(self, context, frontend_config):
        """
        Test that the capabilities returned from the
        .well-known/openid-configuration endpoint are the ones expected.
        """
        expected_scopes_supported = ["openid", "email"]
        frontend_config["scopes_supported"] = expected_scopes_supported
        frontend = create_frontend(frontend_config)

        # Just make sure that these values are in the config
        to_remove = [
            "request_object_signing_alg_values_supported",
            "userinfo_signing_alg_values_supported",
            "id_token_signing_alg_values_supported",
            "userinfo_encryption_enc_values_supported",
            "userinfo_encryption_alg_values_supported",
        ]

        base_url = "{}/{}".format(BASE_URL, frontend.name)
        client_authn_method = [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
        ]

        expected_capabilities = {
            "response_types_supported": response_types_supported,
            "jwks_uri": "{}/jwks".format(base_url),
            "authorization_endpoint": "{}/authorization".format(base_url),
            "token_endpoint": "{}/token".format(base_url),
            "userinfo_endpoint": "{}/userinfo".format(base_url),
            "registration_endpoint": "{}/register".format(base_url),
            "introspection_endpoint": "{}/introspect".format(base_url),
            "revocation_endpoint": "{}/revoke".format(base_url),
            "response_modes_supported": ["query", "form_post"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "claims_supported": [],
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "issuer": base_url,
            "require_request_uri_registration": True,
            "token_endpoint_auth_methods_supported": client_authn_method,
            "token_endpoint_auth_signing_alg_values_supported": get_signing_algs(),
            "version": "3.0",
            "code_challenge_methods_supported": "S256",
        }

        http_response = frontend.handle_provider_info(context)
        provider_config = ProviderConfigurationResponse().deserialize(
            http_response.message, "json"
        )
        provider_config_dict = provider_config.to_dict()
        assert all(provider_config_dict.pop(c, None) is not None for c in to_remove)

        scopes_supported = provider_config_dict.pop("scopes_supported")
        assert set(scopes_supported) == set(expected_scopes_supported)
        assert len(scopes_supported) == len(expected_scopes_supported)

        claims_supported = available_claims(frontend.server.context)
        expected_claims_supported = ["email_verified", "given_name", "sub", "email"]
        assert set(claims_supported) == set(expected_claims_supported)
        assert len(claims_supported) == len(expected_claims_supported)
        assert set(provider_config_dict) == set(expected_capabilities)

    def test_provider_info_allowed_scopes(self, context, frontend_config):
        """
        Test that the capabilities returned from the
        .well-known/openid-configuration endpoint are the ones expected.
        """
        expected_scopes_supported = ["openid", "email"]
        frontend_config["scopes_supported"] = expected_scopes_supported
        frontend = create_frontend(frontend_config)

        http_response = frontend.handle_provider_info(context)
        provider_config = ProviderConfigurationResponse().deserialize(
            http_response.message, "json"
        )
        provider_config_dict = provider_config.to_dict()

        scopes_supported = provider_config_dict.pop("scopes_supported")
        assert set(scopes_supported) == set(expected_scopes_supported)
        assert len(scopes_supported) == len(expected_scopes_supported)

        claims_supported = available_claims(frontend.server.context)
        expected_claims_supported = ["email_verified", "given_name", "sub", "email"]
        assert set(claims_supported) == set(expected_claims_supported)
        assert len(claims_supported) == len(expected_claims_supported)

    def test_provider_info_scopes_supported(self, context, frontend_config):
        """
        Test that the capabilities returned from the
        .well-known/openid-configuration endpoint are the ones expected.
        """
        expected_scopes_supported = ["openid", "email", "eduperson"]
        frontend_config["scopes_supported"] = expected_scopes_supported
        frontend = create_frontend_extra_scopes(frontend_config)

        http_response = frontend.handle_provider_info(context)
        provider_config = ProviderConfigurationResponse().deserialize(
            http_response.message, "json"
        )
        provider_config_dict = provider_config.to_dict()

        scopes_supported = provider_config_dict.pop("scopes_supported")
        assert set(scopes_supported) == set(expected_scopes_supported)
        assert len(scopes_supported) == len(expected_scopes_supported)

    def test_provider_info_extra_scopes(self, context, frontend_extra_scopes):
        """
        Test that the capabilities returned from the
        .well-known/openid-configuration endpoint are the ones expected.
        """
        expected_scopes_supported = ["openid", "email", "offline_access", "eduperson"]
        # Just make sure that these values are in the config
        to_remove = [
            "request_object_signing_alg_values_supported",
            "userinfo_signing_alg_values_supported",
            "id_token_signing_alg_values_supported",
            "userinfo_encryption_enc_values_supported",
            "userinfo_encryption_alg_values_supported",
        ]

        base_url = "{}/{}".format(BASE_URL, frontend_extra_scopes.name)
        client_authn_method = [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
        ]
        expected_capabilities = {
            "response_types_supported": response_types_supported,
            "jwks_uri": "{}/jwks".format(base_url),
            "authorization_endpoint": "{}/authorization".format(base_url),
            "token_endpoint": "{}/token".format(base_url),
            "userinfo_endpoint": "{}/userinfo".format(base_url),
            "registration_endpoint": "{}/register".format(base_url),
            "introspection_endpoint": "{}/introspect".format(base_url),
            "revocation_endpoint": "{}/revoke".format(base_url),
            "response_modes_supported": ["query", "form_post"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "issuer": base_url,
            "require_request_uri_registration": True,
            "token_endpoint_auth_methods_supported": client_authn_method,
            "token_endpoint_auth_signing_alg_values_supported": get_signing_algs(),
            "version": "3.0",
            "code_challenge_methods_supported": ["S256"],
        }

        http_response = frontend_extra_scopes.handle_provider_info(context)
        provider_config = ProviderConfigurationResponse().deserialize(
            http_response.message, "json"
        )
        provider_config_dict = provider_config.to_dict()

        assert all(provider_config_dict.pop(c, None) is not None for c in to_remove)
        scopes_supported = provider_config_dict.pop("scopes_supported")
        assert set(scopes_supported) == set(expected_scopes_supported)
        assert len(scopes_supported) == len(expected_scopes_supported)
        claims_supported = provider_config_dict.pop("claims_supported")
        expected_claims_supported = [
            "sub",
            "email",
            "email_verified",
            "given_name",
            "eduperson_scoped_affiliation",
            "eduperson_principal_name",
        ]
        assert set(claims_supported) == set(expected_claims_supported)
        assert len(claims_supported) == len(expected_claims_supported)
        assert set(provider_config_dict) == set(expected_capabilities)

    def test_jwks(self, context, frontend):
        """
        Tests the jwks endpoint
        """
        http_response = frontend.handle_jwks(context)
        jwks = load_jwks(http_response.message)
        assert len(jwks) == len(JWKS)
        assert {key.kty for key in jwks} == {key["type"] for key in JWKS}
        for key in jwks:
            assert key.verify()

    def test_all_endpoints_are_published(self, frontend):
        """
        Test that token and userinfo endpoints are published in the case of
        authorization code and hybrid flows.
        """
        urls = frontend.register_endpoints(["test"])
        assert ("^{}/token$".format(frontend.name), frontend.handle_token) in urls
        assert ("^{}/userinfo$".format(frontend.name), frontend.handle_userinfo) in urls

    def test_endpoint_paths(self, frontend, context):
        """
        Test that all endpoint are published correctly (as advertised in the
        wellknown endpoint)
        """
        urls = frontend.register_endpoints(["test"])
        http_response = frontend.handle_provider_info(context)
        provider_config = ProviderConfigurationResponse().deserialize(
            http_response.message, "json"
        )
        provider_config_dict = provider_config.to_dict()
        provider_config_dict = {
            k: v
            for k, v in provider_config_dict.items()
            if (k.endswith("_endpoint") or k == "jwks_uri")
        }

        for url, _ in urls:
            # Rip out regex characters
            url = url[1:-1]
            if url.endswith(".well-known/openid-configuration"):
                continue
            # Append base_url
            url = f"{BASE_URL}/{url}"
            assert url in provider_config_dict.values()

    def test_not_all_endpoints_are_published(self, frontend_config, context):
        """
        Test that token and userinfo endpoints are published in the case of
        implicit flow.
        """
        frontend_config["response_types_supported"] = ["id_token", "id_token token"]
        frontend = create_frontend(frontend_config)

        urls = frontend.register_endpoints(["test"])
        assert ("^{}/token$".format(frontend.name), frontend.handle_token) not in urls
        assert (
            "^{}/userinfo$".format(frontend.name),
            frontend.handle_userinfo,
        ) not in urls

        http_response = frontend.handle_provider_info(context)
        provider_config = (
            ProviderConfigurationResponse()
            .deserialize(http_response.message, "json")
            .to_dict()
        )
        assert "token_endpoint" not in provider_config

    @pytest.mark.parametrize("enable_registration_endpoint", [True, False])
    def test_register_endpoints_dynamic_client_registration(
        self, frontend_config, context, enable_registration_endpoint
    ):
        """
        Test that the client registration endpoint is configurable.
        """
        frontend_config["enable_registration_endpoint"] = enable_registration_endpoint
        frontend = create_frontend(frontend_config)

        urls = frontend.register_endpoints(["test"])
        endpoint = ("^{}/register$".format(frontend.name), frontend.handle_registration)
        assert (endpoint in urls) == enable_registration_endpoint
        provider_info = ProviderConfigurationResponse().deserialize(
            frontend.handle_provider_info(context).message, "json"
        )
        assert (
            "registration_endpoint" in provider_info
        ) == enable_registration_endpoint

    def test_no_scopes(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        authn_req["scope"] = ""
        context.state[frontend.name] = {"oidc_request": authn_req}
        context.request = authn_req
        insert_client(frontend, authn_req["redirect_uri"])

        http_resp = frontend.handle_authn_request(context)

        assert isinstance(http_resp, BadRequest)
        assert json.loads(http_resp.message) == {
            "error": "invalid_request",
            "error_description": "Missing required attribute 'scope'",
        }

    def test_filtered_scopes_per_client(
        self, context, frontend_config, authn_req, insert_client
    ):
        frontend_config["deny_unknown_scopes"] = False
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"allowed_scopes": ["profile"]},
        )

        authn_req["scope"] = "openid email"
        context.state[frontend.name] = {"oidc_request": authn_req}
        context.request = authn_req

        http_resp = frontend._handle_authn_request(context)
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).query)

        assert resp.to_dict() == {
            "error": "invalid_scope",
            "error_description": (
                "The requested scope is invalid, unknown, or malformed."
            ),
            "state": "my_state",
        }

    def test_token_endpoint(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test token endpoint.
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["expires_in"] == token_lifetime
        assert parsed["id_token"]
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert "email" in id_token
        assert "email_verified" not in id_token

    def test_token_different_client(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token endpoint.
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_client(frontend, authn_req["redirect_uri"], client_id="client_id_2")
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format("client_id_2", CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = TokenErrorResponse().deserialize(response.message, "json")

        assert response.status == "400 Bad Request"
        assert parsed["error"] == "invalid_grant"

    def test_token_client_post(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token endpoint.
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
        ).to_dict()

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["expires_in"] == token_lifetime
        assert parsed["id_token"]
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert "email" in id_token
        assert "email_verified" not in id_token

    @pytest.mark.xfail(
        reason="Claims mapped from extra (non-standard) scopes are not "
        "released into the ID token."
    )
    def test_token_endpoint_extra_scopes(
        self, context, frontend_extra_scopes, authn_req_extra_scopes, insert_client
    ):
        """
        Test token endpoint.

        XFAIL: oidcendpoint doesn't allow non default claims in the ID Token
        """
        user_id = "test_user"
        insert_client(frontend_extra_scopes, authn_req_extra_scopes["redirect_uri"])
        insert_userinfo(frontend_extra_scopes, user_id)
        del authn_req_extra_scopes["claims"]
        authn_req_extra_scopes["response_type"] = "code"
        internal_response = setup_for_authn_response(
            context, frontend_extra_scopes, authn_req_extra_scopes
        )
        http_resp = frontend_extra_scopes.handle_authn_response(
            context, internal_response
        )
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req_extra_scopes["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend_extra_scopes.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["id_token"]
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend_extra_scopes.endpoint_context.keyjar, sender=""
        )

        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert "email_verified" not in id_token
        assert (
            id_token["eduperson_scoped_affiliation"]
            == OIDC_USERS["testuser1"]["eduPersonScopedAffiliation"]
        )
        assert (
            id_token["eduperson_principal_name"]
            == OIDC_USERS["testuser1"]["eduPersonPrincipalName"]
        )

    @pytest.mark.parametrize(
        "requested_scopes", ["openid", "openid profile email", "openid profile"]
    )
    @pytest.mark.parametrize(
        "allowed_scopes",
        [["openid"], ["openid", "profile", "email"], ["openid", "profile"]],
    )
    def test_deny_unknown_token_scopes_global_cfg(
        self,
        context,
        frontend_config,
        authn_req,
        requested_scopes,
        allowed_scopes,
        insert_client,
    ):
        """
        Test that unknown scopes are handled correctly
        """
        frontend_config["deny_unknown_scopes"] = True
        frontend_config["id_token_enable_claims_per_client"] = True
        frontend_config["at_enable_claims_per_client"] = True
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={
                "allowed_scopes": allowed_scopes,
                "access_token_claims": {"email": {"essential": "True"}},
                "id_token_claims": {"email": {"essential": "True"}},
            },
        )
        # authentication request
        authn_req["response_type"] = "code id_token token"

        authn_req = AuthorizationRequest(
            redirect_uri=authn_req["redirect_uri"],
            client_id=authn_req["client_id"],
            response_type=authn_req["response_type"],
            scope=requested_scopes,
            state="state",
            nonce="nonce",
        )

        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        resp = frontend.handle_authn_request(context)
        for scope in requested_scopes.split():
            if scope not in allowed_scopes:
                error_response = parse_qs(urlparse(resp.message).query)["error"][0]
                assert error_response == "invalid_scope"

    @pytest.mark.parametrize(
        "requested_scopes", ["openid", "openid profile email", "openid profile"]
    )
    @pytest.mark.parametrize(
        "client_allowed_scopes",
        [["openid"], ["openid", "profile", "email"], ["openid", "profile"]],
    )
    def test_deny_unknown_token_scopes_per_client_cfg(
        self,
        context,
        frontend_config,
        authn_req,
        requested_scopes,
        client_allowed_scopes,
        insert_client,
    ):
        """
        Test that unknown scopes are handled correctly
        """
        frontend_config["allowed_scopes"] = ["openid", "profile"]
        frontend_config["deny_unknown_scopes"] = True
        frontend_config["id_token_enable_claims_per_client"] = True
        frontend_config["at_enable_claims_per_client"] = True
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"allowed_scopes": client_allowed_scopes},
        )
        # authentication request
        authn_req["response_type"] = "code id_token token"

        authn_req = AuthorizationRequest(
            redirect_uri=authn_req["redirect_uri"],
            client_id=authn_req["client_id"],
            response_type=authn_req["response_type"],
            scope=requested_scopes,
            state="state",
            nonce="nonce",
        )

        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        resp = frontend.handle_authn_request(context)
        for scope in requested_scopes.split():
            if scope not in client_allowed_scopes:
                error_response = parse_qs(urlparse(resp.message).query)["error"][0]
                assert error_response == "invalid_scope"

    @pytest.mark.parametrize(
        "requested_scopes", ["openid", "openid profile email", "openid profile"]
    )
    @pytest.mark.parametrize(
        "allowed_scopes",
        [["openid"], ["openid", "profile", "email"], ["openid", "profile"]],
    )
    def test_ignore_unknown_token_scopes_global_cfg(
        self,
        context,
        frontend_config,
        authn_req,
        requested_scopes,
        allowed_scopes,
        insert_client,
    ):
        """
        Test that unknown scopes are handled correctly
        """
        frontend_config["deny_unknown_scopes"] = False
        frontend_config["id_token_enable_claims_per_client"] = False
        frontend_config["at_enable_claims_per_client"] = False
        frontend_config["jwt_access_token"] = True
        frontend_config["enable_introspection_endpoint"] = True
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={
                "allowed_scopes": allowed_scopes,
            },
        )
        # authentication request
        authn_req["response_type"] = "code id_token token"

        authn_req = AuthorizationRequest(
            redirect_uri=authn_req["redirect_uri"],
            client_id=authn_req["client_id"],
            response_type=authn_req["response_type"],
            scope=requested_scopes,
            state="state",
            nonce="nonce",
        )

        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend.handle_authn_request(context)
        # fake authentication response from backend
        internal_response = setup_for_authn_response(context, frontend, context.request)
        http_response = frontend.handle_authn_response(context, internal_response)

        # Tokens request
        code = parse_qs(urlparse(http_response.message).fragment)["code"][0]
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)
        response = frontend.handle_token(context)
        response = AccessTokenResponse().deserialize(response.message, "json")

        # Access Token
        access_token = AuthorizationResponse().from_jwt(
            response["access_token"], frontend.endpoint_context.keyjar, sender=""
        )
        if "email" in requested_scopes and "email" not in allowed_scopes:
            assert "email" not in access_token["scope"]
            assert "email" not in response
            assert "email" not in access_token
            assert "email_verified" not in access_token

        # ID Token
        id_token = AuthorizationResponse().from_jwt(
            response["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        if "email" in requested_scopes and "email" not in allowed_scopes:
            assert "email" not in id_token
            assert "email_verified" not in id_token

        # userinfo request
        context.request_authorization = "Bearer {}".format(response["access_token"])
        http_response = frontend.handle_userinfo(context)
        result = OpenIDSchema().deserialize(http_response.message, "json")
        if "email" in requested_scopes and "email" not in allowed_scopes:
            assert "email" not in result

        # introspection
        user_id = "test_user"
        context.request_authorization = "Basic {}".format(basic_auth)
        frontend.register_endpoints(["test_backend"])
        insert_userinfo(frontend, user_id)
        introspection_request = TokenIntrospectionRequest(
            token=response["access_token"]
        )
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )
        assert "active" in intro_resp
        assert intro_resp["active"] is True
        if "email" in requested_scopes and "email" not in allowed_scopes:
            assert "email" not in intro_resp["scope"]
            assert "email" not in intro_resp

    @pytest.mark.parametrize(
        "requested_scopes", ["openid", "openid profile email", "openid profile"]
    )
    @pytest.mark.parametrize(
        "client_allowed_scopes",
        [["openid"], ["openid", "profile", "email"], ["openid", "profile"]],
    )
    def test_ignore_unknown_token_scopes_per_client_cfg(
        self,
        context,
        frontend_config,
        authn_req,
        requested_scopes,
        client_allowed_scopes,
        insert_client,
    ):
        """
        Test that unknown scopes are handled correctly
        """
        frontend_config["allowed_scopes"] = ["openid", "profile"]
        frontend_config["deny_unknown_scopes"] = False
        frontend_config["id_token_enable_claims_per_client"] = True
        frontend_config["at_enable_claims_per_client"] = True
        frontend_config["jwt_access_token"] = True
        frontend_config["enable_introspection_endpoint"] = True
        frontend_config["enable_introspection_claims_per_client"] = True
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={
                "allowed_scopes": client_allowed_scopes,
            },
        )
        # authentication request
        authn_req["response_type"] = "code id_token token"

        authn_req = AuthorizationRequest(
            redirect_uri=authn_req["redirect_uri"],
            client_id=authn_req["client_id"],
            response_type=authn_req["response_type"],
            scope=requested_scopes,
            state="state",
            nonce="nonce",
        )

        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend.handle_authn_request(context)
        # fake authentication response from backend
        internal_response = setup_for_authn_response(context, frontend, context.request)
        http_response = frontend.handle_authn_response(context, internal_response)

        # Tokens request
        code = parse_qs(urlparse(http_response.message).fragment)["code"][0]
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)
        response = frontend.handle_token(context)
        response = AccessTokenResponse().deserialize(response.message, "json")

        # Access Token
        access_token = AuthorizationResponse().from_jwt(
            response["access_token"], frontend.endpoint_context.keyjar, sender=""
        )
        if "email" in requested_scopes and "email" not in client_allowed_scopes:
            assert "email" not in access_token["scope"]
            assert "email" not in access_token
            assert "email_verified" not in access_token

        # ID Token
        id_token = AuthorizationResponse().from_jwt(
            response["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        if "email" in requested_scopes and "email" not in client_allowed_scopes:
            assert "email" not in id_token
            assert "email_verified" not in id_token

        # userinfo request
        context.request_authorization = "Bearer {}".format(response["access_token"])
        http_response = frontend.handle_userinfo(context)
        result = OpenIDSchema().deserialize(http_response.message, "json")
        if "email" in requested_scopes and "email" not in client_allowed_scopes:
            assert "email" not in response
            assert "email" not in result
            assert "email_verified" not in result

        # introspection
        user_id = "test_user"
        context.request_authorization = "Basic {}".format(basic_auth)
        insert_userinfo(frontend, user_id)
        introspection_request = TokenIntrospectionRequest(
            token=response["access_token"]
        )
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )
        assert "active" in intro_resp
        assert intro_resp["active"] is True
        if "email" in requested_scopes and "email" not in client_allowed_scopes:
            assert "email" not in intro_resp["scope"]
            assert "email" not in intro_resp

    @pytest.mark.xfail(
        reason="idpyoidc raises KeyError on the non-standard requested claim "
        "(eduperson_principal_name) instead of ignoring it."
    )
    def test_token_endpoint_claims_not_in_scope(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the token endpoint ignores any claims that are not present

        XFAIL: oidcendpoint doesn't allow non default claims in the ID Token
        """
        token_lifetime = 60 * 60 * 24
        internal_attributes = copy.deepcopy(INTERNAL_ATTRIBUTES)
        internal_attributes["attributes"].update(EXTRA_CLAIMS)
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(
            frontend_config, internal_attributes=internal_attributes
        )

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["claims"]["id_token"]["eduperson_scoped_affiliation"] = {
            "essential": True
        }
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["expires_in"] == token_lifetime
        assert parsed["id_token"]
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert "email_verified" not in id_token
        assert (
            id_token["eduperson_scoped_affiliation"]
            == OIDC_USERS["testuser1"]["eduPersonScopedAffiliation"]
        )
        assert (
            id_token["eduperson_principal_name"]
            == OIDC_USERS["testuser1"]["eduPersonPrincipalName"]
        )

    def test_token_endpoint_unknown_claims(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the token endpoint ignores any claims that are not present
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["claims"]["id_token"]["aba"] = {"essential": True}
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["expires_in"] == token_lifetime
        assert parsed["id_token"]
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert "email" in id_token
        assert "email_verified" not in id_token
        assert "aba" not in id_token

    def test_idtoken_default_claims(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the default claims are added to the id token.
        """
        frontend_config["id_token_default_claims"] = ["email_verified"]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        id_token = AuthorizationResponse().from_jwt(
            resp["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert id_token["email_verified"] == OIDC_USERS["testuser1"]["email_verified"]

    def test_idtoken_claims_per_client(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the default claims are added to the id token.
        """
        frontend_config["id_token_enable_claims_per_client"] = True
        frontend = create_frontend(frontend_config)
        client_claims = {
            "add_claims": {"always": {"id_token": {"email_verified": None}}}
        }
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=client_claims)
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        id_token = AuthorizationResponse().from_jwt(
            resp["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert id_token["email_verified"] == OIDC_USERS["testuser1"]["email_verified"]

    def test_access_token_claims_per_client(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the default claims are added to the id token.
        """
        frontend_config["at_enable_claims_per_client"] = True
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        client_claims = {
            "add_claims": {"always": {"access_token": {"email_verified": None}}}
        }
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=client_claims)
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        access_token = AuthorizationResponse().from_jwt(
            resp["access_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert (
            access_token["email_verified"] == OIDC_USERS["testuser1"]["email_verified"]
        )

    def test_access_token_scopes(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that scopes are added to the access token
        """
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        # authn_req["scope"] = "openid email aba"
        authn_req["scope"] = "openid email"
        client_claims = {"token_claims": {"email_verified": None}}
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=client_claims)
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        resp = AuthorizationResponse().deserialize(urlparse(http_resp.message).fragment)
        access_token = AuthorizationResponse().from_jwt(
            resp["access_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert set(access_token["scope"]) == {"openid", "email"}

    @pytest.mark.parametrize(
        "grant_types_supported",
        [["authorization_code"], ["authorization_code", "refresh_token"]],
    )
    def test_refresh_token_issued(
        self, context, frontend_config, authn_req, grant_types_supported, insert_client
    ):
        """
        Test that a refresh token is issued only if configured.
        """
        frontend_config["grant_types_supported"] = grant_types_supported
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert ("refresh_token" in parsed) is ("refresh_token" in grant_types_supported)

    def test_bearer_header_authz(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test Bearer Header authorization in token endpoint
        """
        grant_types_supported = ["authorization_code", "refresh_token"]
        frontend_config["grant_types_supported"] = grant_types_supported
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        context.request_authorization = "Bearer {}".format(code)

        response = frontend.handle_token(context)
        assert json.loads(response.message) == {
            "error": "invalid_client",
            "error_description": "Authorization failed",
        }

    def test_not_supported_grant_type_per_client(
        self, context, authn_req, frontend, insert_client
    ):
        """
        Test the grant_types_supported config is respected
        """
        metadata = {"grant_types_supported": ["authorization_code"]}

        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=metadata)

        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        assert "access_token" in parsed
        assert "id_token" in parsed
        assert "refresh_token" in parsed

        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], scope="openid"
        )
        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        assert parsed.to_dict() == {
            "error": "invalid_request",
            "error_description": "Unsupported grant_type: refresh_token",
        }

    def test_refresh_token_different_scopes(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that a refresh token is issued only if configured.
        """
        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] = "openid offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        )
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        assert parsed["refresh_token"]

        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], scope="openid offline email access"
        )

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        assert parsed.to_dict() == {
            "error": "invalid_request",
            "error_description": "Invalid refresh scopes",
        }

    def test_refresh_token_more_scopes(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that a refresh token is issued only if configured.
        """
        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] = "openid offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        )
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        assert parsed["refresh_token"]

        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], scope="openid offline_access email"
        )

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        assert parsed.to_dict() == {
            "error": "invalid_request",
            "error_description": "Invalid refresh scopes",
        }

    def test_refresh_token_less_scopes(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that a refresh token is issued only if configured.
        """
        frontend_config["id_token_add_claims_by_scope"] = True
        frontend = create_frontend(frontend_config)
        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] = "openid offline_access email"
        authn_req["prompt"] = "consent"
        authn_req.pop("claims")
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        )
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert parsed["refresh_token"]
        assert "email" in id_token

        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], scope="openid offline_access"
        )

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token_2 = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert "access_token" in parsed
        assert "refresh_token" in parsed
        assert "id_token" in parsed
        assert "email" not in id_token_2
        assert set(parsed["scope"]) == set(["openid", "offline_access"])

    def test_refresh_token_not_issued(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that a refresh token is not issued if no offline access scope is
        requested even if it is configured.
        """
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "refresh_token" not in parsed

    def test_revoke_refresh_on_issue_global(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the refresh token is revoked upon issuing a new one.
        """
        frontend_config["grant_types_supported"] = [
            "authorization_code",
            "refresh_token",
        ]
        frontend_config["revoke_refresh_on_issue"] = True
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["refresh_token"])["grant"]
        token = grant.get_token(parsed["refresh_token"])
        assert token.is_active()

        # Issue refresh token
        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], grant_type="refresh_token"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response_first = frontend.handle_token(context)
        parsed_first = AccessTokenResponse().deserialize(response_first.message, "json")
        grant = frontend._load_session_from_token(parsed["refresh_token"])["grant"]
        token = grant.get_token(parsed["refresh_token"])
        grant2 = frontend._load_session_from_token(parsed_first["refresh_token"])[
            "grant"
        ]
        token2 = grant2.get_token(parsed_first["refresh_token"])
        assert token.is_active() is False
        assert token2.is_active()

        # Issue second refresh token
        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], grant_type="refresh_token"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response_second = frontend.handle_token(context)
        parsed_second = AccessTokenResponse().deserialize(
            response_second.message, "json"
        )
        assert parsed_second.to_dict() == {
            "error": "invalid_request",
            "error_description": "Refresh token inactive",
        }

    def test_revoke_refresh_on_issue_per_client(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that the refresh token is revoked upon issuing a new one.
        """
        frontend_config["grant_types_supported"] = [
            "authorization_code",
            "refresh_token",
        ]
        frontend_config["revoke_refresh_on_issue"] = False
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"revoke_refresh_on_issue": True},
        )
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["refresh_token"])["grant"]
        token = grant.get_token(parsed["refresh_token"])
        assert token.is_active()

        # Issue refresh token
        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], grant_type="refresh_token"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response_first = frontend.handle_token(context)
        parsed_first = AccessTokenResponse().deserialize(response_first.message, "json")
        grant = frontend._load_session_from_token(parsed["refresh_token"])["grant"]
        token = grant.get_token(parsed["refresh_token"])
        grant2 = frontend._load_session_from_token(parsed_first["refresh_token"])[
            "grant"
        ]
        token2 = grant2.get_token(parsed_first["refresh_token"])
        assert token.is_active() is False
        assert token2.is_active()

        # Issue second refresh token
        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], grant_type="refresh_token"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response_second = frontend.handle_token(context)
        parsed_second = AccessTokenResponse().deserialize(
            response_second.message, "json"
        )
        assert parsed_second.to_dict() == {
            "error": "invalid_request",
            "error_description": "Refresh token inactive",
        }

    def test_userinfo_without_openid(
        self, context, frontend_config, authn_req, insert_client
    ):

        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={
                "allowed_scopes": ["profile"],
            },
        )

        context.request = CCAccessTokenRequest(
            grant_type="client_credentials",
            scope="",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]

        # Access Token
        access_token = AuthorizationResponse().from_jwt(
            parsed["access_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert "openid" not in access_token.get("scope", [])
        # userinfo request
        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        context.request = {}
        response = frontend.handle_userinfo(context)
        assert response.message.to_dict() == {
            "error": "invalid_token",
            "error_description": "Invalid Token",
        }

    def test_userinfo_expired_access_token(
        self, context, frontend_config, authn_req, monkeypatch, insert_client
    ):
        def mock():
            return utc_time_sans_frac() + 3600 + 1

        frontend_config["grant_types_supported"] = [
            "authorization_code",
            "refresh_token",
        ]
        frontend_config["revoke_refresh_on_issue"] = False
        frontend_config["access_token_lifetime"] = 600
        frontend_config["refresh_token_lifetime"] = 9000
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]
        token = grant.get_token(parsed["access_token"])
        assert token.is_active()

        monkeypatch.setattr("idpyoidc.server.token.utc_time_sans_frac", mock)
        monkeypatch.setattr("idpyoidc.server.session.token.utc_time_sans_frac", mock)
        assert token.is_active() is False

        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        context.request = {}
        response = frontend.handle_userinfo(context)
        assert response.message.to_dict() == {
            "error": "invalid_token",
            "error_description": "Invalid Token",
        }

    def test_userinfo_revoked_access_token(
        self, context, frontend_config, authn_req, monkeypatch, insert_client
    ):
        frontend_config["grant_types_supported"] = [
            "authorization_code",
            "refresh_token",
        ]
        frontend_config["revoke_refresh_on_issue"] = False
        frontend_config["access_token_lifetime"] = 600
        frontend_config["refresh_token_lifetime"] = 9000
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]
        token = grant.get_token(parsed["access_token"])
        assert token.is_active()

        context.request = TokenRevocationRequest(
            token=parsed["access_token"],
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token_revocation(context)
        assert response.message == "OK"
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]
        token = grant.get_token(parsed["access_token"])
        assert token.revoked
        assert token.is_active() is False
        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        context.request = {}
        response = frontend.handle_userinfo(context)
        assert response.message.to_dict() == {
            "error": "invalid_token",
            "error_description": "Invalid Token",
        }

    def test_refreshing_access_token(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that a refresh token can be used to refresh an access token.

        Refresh tokens are issued when offline_access is granted; the
        refresh response carries a new access token and a rotated refresh
        token. Single-use semantics for the old refresh token are covered
        by the test_revoke_refresh_on_issue_* tests.
        """
        frontend_config["refresh_token_lifetime"] = 86400
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "refresh_token" in parsed
        first_access_token = parsed["access_token"]
        first_refresh_token = parsed["refresh_token"]

        context.request = RefreshAccessTokenRequest(
            refresh_token=first_refresh_token, grant_type="refresh_token"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "access_token" in parsed
        assert parsed["access_token"] != first_access_token
        # offline_access drives issue_refresh, so the refresh response
        # carries a rotated refresh token.
        assert "refresh_token" in parsed
        assert parsed["refresh_token"] != first_refresh_token
        second_access_token = parsed["access_token"]

        # The second access token should be valid
        context.request_authorization = "Bearer {}".format(second_access_token)
        response = frontend.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert response.status == "200 OK"
        assert "sub" in parsed

    def test_token_endpoint_invalid_client(self, context, frontend, authn_req):
        """
        Test that a 401 response is returned if invalid client credentials are
        used.
        """
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code="code"
        ).to_dict()
        credentials = "{}:{}".format("unknown", "unknown")
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert response.status == "400 Bad Request"
        assert parsed_message["error"] == "invalid_client"

    def test_token_endpoint_invalid_code(
        self, context, frontend, authn_req, insert_client
    ):
        insert_client(frontend, authn_req["redirect_uri"])
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code="invalid"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert response.status == "400 Bad Request"
        assert parsed_message["error"] == "invalid_grant"

    def test_token_endpoint_reuse_code(
        self, context, frontend, authn_req, insert_client
    ):
        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"

        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert response.status == "200 OK"

        # The second call should fail
        response = frontend.handle_token(context)
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert response.status == "400 Bad Request"
        assert parsed_message["error"] == "invalid_grant"

    def test_userinfo_endpoint(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test the userinfo endpoint.
        """
        user_id = OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        authn_req["scope"] = "openid email"

        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        token = self.create_access_token(context, frontend, authn_req)
        context.request = {}
        context.request_authorization = "Bearer {}".format(token)
        response = frontend.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"

    def test_userinfo_endpoint_get_params(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test the userinfo endpoint.
        """
        user_id = OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        authn_req["scope"] = "openid email"

        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        token = self.create_access_token(context, frontend, authn_req)
        context.request = {"access_token": token}
        context.request_method = "GET"
        response = frontend.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")

        assert parsed.to_dict() == {
            "error": "invalid_token",
            "error_description": "Invalid token",
        }

    def test_userinfo_endpoint_post_header(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test the userinfo endpoint.
        """
        user_id = OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        authn_req["scope"] = "openid email"

        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        token = self.create_access_token(context, frontend, authn_req)
        context.request = {}
        context.request_method = "POST"
        context.request_authorization = "Bearer {}".format(token)
        response = frontend.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"

    def test_userinfo_request_method(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test that requests to the userinfo endpoint are allowed both for GET and POST
        request method.
        """
        user_id = OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        authn_req["scope"] = "openid email"

        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        token = self.create_access_token(context, frontend, authn_req)
        context.request = {}
        context.request_method = "POST"
        context.request_authorization = "Bearer {}".format(token)
        response = frontend.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"

        context.request_method = "GET"
        context.request_authorization = "Bearer {}".format(token)
        response = frontend.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"

    def test_registration_request_method(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that a client can register successfully only with POST requests
        """
        insert_client(frontend, authn_req["redirect_uri"])
        token = self.create_access_token(context, frontend, authn_req)
        context.request_authorization = "Bearer {}".format(token)

        redirect_uri = "https://newclient.example.com"
        registration_request = RegistrationRequest(
            redirect_uris=[redirect_uri],
            response_types=["id_token"],
            client_id=authn_req["client_id"],
        )
        context.request = registration_request.to_dict()
        context.request_method = "POST"
        registration_response = frontend.handle_registration(context)
        assert registration_response.status == "201 Created"

        reg_resp = RegistrationResponse().deserialize(
            registration_response.message, "json"
        )
        assert "client_id" in reg_resp
        assert reg_resp["redirect_uris"] == [redirect_uri]
        assert reg_resp["response_types"] == ["id_token"]

        context.request_method = "GET"
        registration_response = frontend.handle_registration(context)

        assert isinstance(registration_response, BadRequest)
        assert registration_response.message == "invalid_request"

    def test_handle_introspection_request_method(
        self, context, frontend_config, authn_req, insert_client
    ):
        user_id = "test_user"
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        context.request_method = "GET"
        introspection_response = frontend.handle_introspection(context)
        assert isinstance(introspection_response, BadRequest)
        assert introspection_response.message == "invalid_request"

        context.request_method = "POST"
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        attributes = frontend.converter.from_internal(
            "openid", internal_response.attributes
        )
        sub = attributes.get("sub", [None])[0]

        assert intro_resp["active"] is True
        assert intro_resp["client_id"] == authn_req["client_id"]
        assert intro_resp["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert intro_resp["sub"] == sub
        assert intro_resp["token_type"] == "Bearer"
        assert intro_resp["scope"] == authn_req["scope"]
        assert "iat" in intro_resp
        assert "exp" in intro_resp

    def test_token_request_method(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token endpoint for different request methods.
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        context.request_method = "GET"
        response = frontend.handle_token(context)
        assert isinstance(response, BadRequest)
        assert response.message == "invalid_request"

        context.request_method = "POST"
        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["expires_in"] == token_lifetime
        assert parsed["id_token"]
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert "email" in id_token
        assert "email_verified" not in id_token

    def test_userinfo_endpoint_post_params(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test the userinfo endpoint.
        """
        user_id = OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        authn_req["scope"] = "openid email"

        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        token = self.create_access_token(context, frontend, authn_req)
        context.request = {"access_token": token}
        context.request_method = "POST"
        response = frontend.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"

    def test_userinfo_claims(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that the userinfo endpoint adds the requested claims to the request.
        """
        user_id = OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        authn_req["scope"] = "openid email"
        frontend = create_frontend_extra_scopes(frontend_config)

        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["claims"]["userinfo"] = dict(eduperson_scoped_affiliation=None)
        token = self.create_access_token(context, frontend, authn_req)
        context.request = {}
        context.request_authorization = "Bearer {}".format(token)
        response = frontend.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"
        assert parsed["eduperson_scoped_affiliation"] == ["student@example.com"]

    def test_userinfo_endpoint_extra_scopes(
        self, context, frontend_extra_scopes, authn_req_extra_scopes, insert_client
    ):
        """
        Test the userinfo endpoint with extra scopes.
        """
        user_id = OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        insert_client(frontend_extra_scopes, authn_req_extra_scopes["redirect_uri"])
        insert_userinfo(frontend_extra_scopes, user_id)
        token = self.create_access_token(
            context, frontend_extra_scopes, authn_req_extra_scopes
        )
        context.request = {}
        context.request_authorization = "Bearer {}".format(token)
        response = frontend_extra_scopes.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"
        assert parsed["eduperson_scoped_affiliation"] == ["student@example.com"]
        assert parsed["eduperson_principal_name"] == ["test@example.com"]

    def test_userinfo_endpoint_per_client_scopes(
        self, context, frontend_extra_scopes, authn_req_extra_scopes, insert_client
    ):
        """
        The allowed_scopes client parameter must override the extra_scopes
        """
        user_id = OIDC_USERS["testuser1"]["eduPersonTargetedID"][0]
        insert_client(
            frontend_extra_scopes,
            authn_req_extra_scopes["redirect_uri"],
            extra_metadata={"allowed_scopes": "openid email"},
        )
        insert_userinfo(frontend_extra_scopes, user_id)
        token = self.create_access_token(
            context, frontend_extra_scopes, authn_req_extra_scopes
        )
        context.request = {}
        context.request_authorization = "Bearer {}".format(token)
        response = frontend_extra_scopes.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(response.message, "json")
        assert parsed["email"] == "test@example.com"
        assert "eduperson_scoped_affiliation" not in parsed
        assert "eduperson_principal_name" not in parsed

    def test_userinfo_invalid_token(self, context, frontend):
        context.request = {}
        context.request_authorization = "Bearer invalid"

        response = frontend.handle_userinfo(context)
        assert response.status == "401 Unauthorized"

    def test_userinfo_no_header(self, context, frontend):
        context.request = {}

        response = frontend.handle_userinfo(context)
        assert response.status == "401 Unauthorized"

    def test_client_metadata_in_context(
        self, context, frontend, authn_req, insert_client
    ):
        """
        Test that the frontend handles the authentication request properly.
        """
        mock_callback = Mock()
        frontend.auth_req_callback_func = mock_callback
        client_name = "test client"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={
                "client_name": client_name,
                "client_secret": 123,
                "aba": "bab",
            },
        )

        context.request = authn_req
        frontend.handle_authn_request(context)

        assert mock_callback.call_count == 1
        context, internal_req = mock_callback.call_args[0]

        client_metadata = context.get_decoration(KEY_REQUESTER_METADATA)
        assert "client_secret" not in client_metadata
        assert "aba" in client_metadata
        assert client_metadata["aba"] == "bab"

    def test_code_flow(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test response_type = code
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        parsed = parse_qs(urlparse(http_resp.message).query)
        assert "id_token" not in parsed
        assert "access_token" not in parsed

        code = parsed["code"][0]
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "id_token" in parsed
        assert "access_token" in parsed

    def test_token_flow(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test response_type = token
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        # If the flow is not code then response_mode is set to fragment
        parsed = parse_qs(urlparse(http_resp.message).fragment)
        assert "id_token" not in parsed
        assert "code" not in parsed
        assert "access_token" in parsed

    def test_idtoken_flow(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test response_type = id_token
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "id_token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        # If the flow is not code then response_mode is set to fragment
        parsed = parse_qs(urlparse(http_resp.message).fragment)
        assert "id_token" in parsed
        assert "code" not in parsed
        assert "access_token" not in parsed

    def test_code_token_flow(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test response_type = code token
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        # If the flow is not code then response_mode is set to fragment
        parsed = parse_qs(urlparse(http_resp.message).fragment)
        assert "id_token" not in parsed
        assert "code" in parsed
        assert "access_token" in parsed

        code = parsed["code"][0]
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed_token = AccessTokenResponse().deserialize(response.message, "json")
        assert "id_token" in parsed_token
        assert "access_token" in parsed_token

    def test_code_idtoken_flow(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test response_type = code id_token
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        # If the flow is not code then response_mode is set to fragment
        parsed = parse_qs(urlparse(http_resp.message).fragment)
        assert "id_token" in parsed
        assert "code" in parsed
        assert "access_token" not in parsed

        code = parsed["code"][0]
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed_token = AccessTokenResponse().deserialize(response.message, "json")
        assert "id_token" in parsed_token
        assert "access_token" in parsed_token

    def test_token_idtoken_flow(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test response_type = token id_token
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "token id_token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        # If the flow is not code then response_mode is set to fragment
        parsed = parse_qs(urlparse(http_resp.message).fragment)
        assert "id_token" in parsed
        assert "code" not in parsed
        assert "access_token" in parsed

    def test_code_token_idtoken_flow(
        self,
        context,
        frontend,
        authn_req,
        insert_client,
    ):
        """
        Test response_type = code id_token token
        """
        insert_client(frontend, authn_req["redirect_uri"])
        authn_req["response_type"] = "code id_token token"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        # If the flow is not code then response_mode is set to fragment
        parsed = parse_qs(urlparse(http_resp.message).fragment)
        assert "id_token" in parsed
        assert "code" in parsed
        assert "access_token" in parsed

        code = parsed["code"][0]
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed_token = AccessTokenResponse().deserialize(response.message, "json")
        assert "id_token" in parsed_token
        assert "access_token" in parsed_token

    def test_full_flow(
        self,
        context,
        frontend_extra_scopes,
        authn_req,
        insert_client,
    ):
        redirect_uri = "https://client.example.com/redirect"
        response_type = "code id_token token"

        mock_callback = Mock()
        frontend_extra_scopes.auth_req_callback_func = mock_callback
        # discovery
        http_response = frontend_extra_scopes.handle_provider_info(context)
        ProviderConfigurationResponse().deserialize(http_response.message, "json")

        insert_client(frontend_extra_scopes, redirect_uri)

        # authentication request
        authn_req = AuthorizationRequest(
            redirect_uri=redirect_uri,
            client_id=CLIENT_ID,
            response_type=response_type,
            scope="openid email eduperson",
            state="state",
            nonce="nonce",
        )
        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend_extra_scopes.handle_authn_request(context)
        assert mock_callback.call_count == 1

        # fake authentication response from backend
        internal_response = setup_for_authn_response(
            context, frontend_extra_scopes, authn_req.to_dict()
        )
        http_response = frontend_extra_scopes.handle_authn_response(
            context, internal_response
        )
        authn_resp = AuthorizationResponse().deserialize(
            urlparse(http_response.message).fragment, "urlencoded"
        )
        assert "code" in authn_resp
        assert "access_token" in authn_resp
        assert "id_token" in authn_resp

        # token request
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        http_response = frontend_extra_scopes.handle_token(context)
        parsed = AccessTokenResponse().deserialize(http_response.message, "json")
        assert "access_token" in parsed
        assert "id_token" in parsed

        # userinfo request
        context.request = {}
        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        http_response = frontend_extra_scopes.handle_userinfo(context)
        parsed = OpenIDSchema().deserialize(http_response.message, "json")
        assert "email" in parsed
        assert "eduperson_principal_name" in parsed
        assert "eduperson_scoped_affiliation" in parsed

        redirect_uri = "https://newclient.example.com/redirect"

        # client registration
        registration_request = RegistrationRequest(
            redirect_uris=[redirect_uri], response_types=[response_type]
        )
        context.request = registration_request.to_dict()
        http_response = frontend_extra_scopes.handle_registration(context)
        RegistrationResponse().deserialize(http_response.message, "json")

    @pytest.mark.parametrize("pkce_essential", [True, False])
    def test_pkce_no_code(
        self, context, frontend_config, authn_req, pkce_essential, insert_client
    ):
        """
        Test that a code is required with pkce enabled and essential.
        """
        frontend_config["pkce"] = {"essential": pkce_essential}

        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)

        authn_req["response_type"] = "code"

        context.request = authn_req
        resp = frontend.handle_authn_request(context)

        if pkce_essential:
            message = json.loads(resp.message)
            assert resp.status == "400 Bad Request"
            assert message["error"] == "invalid_request"
            assert message["error_description"] == ("Missing required code_challenge")
        else:
            assert resp is None

    def test_pkce_wrong_code_or_missing(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that pkce works by not issuing a token with wrong code or missing.
        """
        frontend_config["pkce"] = {"essential": False}

        user_id = "test_user"
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["code_challenge"] = "testtesttest"
        authn_req["code_challenge_method"] = "S256"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        authn_resp = parse_qs(urlparse(http_resp.message).query)
        assert "code" in authn_resp

        # token request with wrong code_verifier
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=authn_resp["code"][0],
            code_verifier="wrong",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        assert response.status == "400 Bad Request"
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert parsed_message["error"] == "invalid_grant"

        # token request with no code_verifier
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        assert response.status == "400 Bad Request"
        parsed_message = TokenErrorResponse().deserialize(response.message, "json")
        assert parsed_message["error"] == "invalid_grant"

    def test_pkce_no_plain(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that code_challenge_methods are passed to oidcendpoint.
        """
        code_challenge_methods = CC_METHOD.copy()
        code_challenge_methods.pop("plain")
        frontend_config["pkce"] = {
            "essential": True,
            "code_challenge_methods": code_challenge_methods,
        }

        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)

        authn_req["response_type"] = "code"

        context.request = authn_req
        resp = frontend.handle_authn_request(context)
        message = json.loads(resp.message)
        assert resp.status == "400 Bad Request"
        assert message["error"] == "invalid_request"
        assert message["error_description"] == ("Missing required code_challenge")

    @pytest.mark.parametrize("pkce_conf", [{"essential": False}, True])
    def test_pkce_flow(
        self, context, frontend_config, authn_req, pkce_conf, insert_client
    ):
        """
        Test that pkce works.
        """
        frontend_config["pkce"] = pkce_conf

        user_id = "test_user"
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        _cc_info = _code_challenge()
        authn_req["response_type"] = "code"
        authn_req["code_challenge"] = _cc_info["code_challenge"]
        authn_req["code_challenge_method"] = _cc_info["code_challenge_method"]
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        authn_resp = parse_qs(urlparse(http_resp.message).query)
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=authn_resp["code"][0],
            code_verifier=_cc_info["code_verifier"],
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        http_response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(http_response.message, "json")
        assert "access_token" in parsed

    @pytest.mark.parametrize("per_client", [True, False])
    def test_authorization_code_lifetime(
        self, context, frontend_config, authn_req, per_client, insert_client
    ):
        """
        Test that we can configure the lifetime of the authorization_code globally and
        per client
        """
        lifetime = 100
        usage_rules = {}
        if per_client:
            usage_rules = {
                "token_usage_rules": {"authorization_code": {"expires_in": lifetime}}
            }
        else:
            frontend_config["code_lifetime"] = lifetime
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        grant = frontend._load_session_from_token(authn_resp["code"][0])["grant"]

        assert grant.usage_rules["authorization_code"]["expires_in"] == lifetime
        token = grant.get_token(authn_resp["code"][0])
        assert token.expires_at - token.issued_at == lifetime

    @pytest.mark.parametrize("per_client", [True, False])
    def test_authorization_code_no_lifetime(
        self, context, frontend_config, authn_req, per_client, insert_client
    ):
        """
        Test that we can configure the lifetime of the authorization_code to never
        expire
        """
        lifetime = 0
        usage_rules = {}
        if per_client:
            usage_rules = {
                "token_usage_rules": {"authorization_code": {"expires_in": lifetime}}
            }
        else:
            frontend_config["code_lifetime"] = lifetime
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        grant = frontend._load_session_from_token(authn_resp["code"][0])["grant"]

        assert grant.usage_rules["authorization_code"]["expires_in"] == lifetime
        token = grant.get_token(authn_resp["code"][0])
        assert token.expires_at == 0
        # The token should never expire
        assert token.is_active(now=99999999999)
        
    def test_authorization_code_missing_prompt(
        self, context, authn_req, frontend_config, insert_client
    ):
        """
        Test that an OIDC authentication request including 'offline_access' scope
        but missing the 'prompt' parameter is correctly handled.
        """
        frontend_config["jwt_access_token"] = True

        frontend = create_frontend(frontend_config)  
        insert_client(frontend, authn_req["redirect_uri"])

        # authentication request including offline_access scope but without prompt parameter
        authn_req["response_type"] = "code id_token token"
        authn_req = AuthorizationRequest(
            redirect_uri=authn_req["redirect_uri"],
            client_id=authn_req["client_id"],
            response_type=authn_req["response_type"],
            scope="eduperson openid offline_access",
            state="state",
            nonce="nonce",
        )

        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend.handle_authn_request(context)
        internal_response = setup_for_authn_response(context, frontend, context.request)
        http_response = frontend.handle_authn_response(context, internal_response)
        assert http_response.status == "302 Found"
        assert "code" in parse_qs(urlparse(http_response.message).fragment)

    @pytest.mark.parametrize("per_client", [True, False])
    def test_access_token_lifetime(
        self, context, frontend_config, authn_req, per_client, insert_client
    ):
        """
        Test that we can configure the lifetime of the access_token globally and per
        client
        """
        lifetime = 100
        usage_rules = {}
        if per_client:
            usage_rules = {
                "token_usage_rules": {"access_token": {"expires_in": lifetime}}
            }
        else:
            frontend_config["access_token_lifetime"] = lifetime
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]

        assert grant.usage_rules["access_token"]["expires_in"] == lifetime
        token = grant.get_token(parsed["access_token"])
        assert token.expires_at - token.issued_at == lifetime
        assert token.is_active()

    @pytest.mark.parametrize("per_client", [True, False])
    def test_jwt_access_token_lifetime(
        self,
        context,
        frontend_config,
        authn_req,
        per_client,
        monkeypatch,
        insert_client,
    ):
        """
        Test that we can configure the lifetime of the access_token globally and per
        client
        """
        lifetime = 100
        usage_rules = {}
        frontend_config["access_token_lifetime"] = lifetime
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]
        access_token = AuthorizationResponse().from_jwt(
            parsed["access_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert grant.usage_rules["access_token"]["expires_in"] == lifetime
        token = grant.get_token(parsed["access_token"])
        assert token.expires_at - token.issued_at == lifetime
        assert access_token["exp"] - access_token["iat"] == lifetime
        assert token.is_active()

        def mock():
            return utc_time_sans_frac() + lifetime + 1

        monkeypatch.setattr("idpyoidc.server.token.utc_time_sans_frac", mock)

        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        response = frontend.handle_userinfo(context)
        assert json.loads(response.message) == {
            "error": "invalid_token",
            "error_description": "Expired token",
        }

    @pytest.mark.parametrize("per_client", [True, False])
    def test_access_token_no_lifetime(
        self, context, frontend_config, authn_req, per_client, insert_client
    ):
        """
        Test that we can configure the lifetime of the access_token to never
        expire
        """
        lifetime = 0
        usage_rules = {}
        if per_client:
            usage_rules = {
                "token_usage_rules": {"access_token": {"expires_in": lifetime}}
            }
        else:
            frontend_config["access_token_lifetime"] = lifetime
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]

        assert grant.usage_rules["access_token"]["expires_in"] == lifetime
        token = grant.get_token(parsed["access_token"])
        assert token.expires_at == 0
        # The token should never expire
        assert token.is_active(now=99999999999)

    @pytest.mark.parametrize(
        "grant_types_supported, global_grant_types_supported",
        [
            (["authorization_code"], ["authorization_code"]),
            (["authorization_code", "refresh_token"], ["authorization_code"]),
            (
                ["authorization_code", "refresh_token"],
                ["authorization_code", "refresh_token"],
            ),
        ],
    )
    def test_refresh_token_per_client(
        self,
        context,
        frontend_config,
        authn_req,
        grant_types_supported,
        global_grant_types_supported,
        insert_client,
    ):
        """
        Test that we can configure the lifetime of the refresh_token globally and per
        client
        """
        frontend_config["grant_types_supported"] = global_grant_types_supported
        frontend = create_frontend(frontend_config)

        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"grant_types_supported": grant_types_supported},
        )

        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")

        if (
            "refresh_token" in frontend_config["grant_types_supported"]
            and "refresh_token" in grant_types_supported
        ) or (
            "refresh_token" not in frontend_config["grant_types_supported"]
            and "refresh_token" in grant_types_supported
        ):
            assert "refresh_token" in parsed
            first_access_token = parsed["access_token"]
            first_refresh_token = parsed["refresh_token"]

            context.request = RefreshAccessTokenRequest(
                refresh_token=first_refresh_token
            ).to_dict()
            credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
            basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
            context.request_authorization = "Basic {}".format(basic_auth)

            response = frontend.handle_token(context)
            parsed = AccessTokenResponse().deserialize(response.message, "json")
            assert "access_token" in parsed
            assert parsed["access_token"] != first_access_token

            assert "refresh_token" in parsed
            assert parsed["refresh_token"] != first_refresh_token
            second_access_token = parsed["access_token"]

            # The second access token should be valid
            context.request_authorization = "Bearer {}".format(second_access_token)
            response = frontend.handle_userinfo(context)
            parsed = OpenIDSchema().deserialize(response.message, "json")
            assert response.status == "200 OK"
            assert "sub" in parsed
        elif (
            "refresh_token" not in frontend_config["grant_types_supported"]
            and "refresh_token" not in grant_types_supported
        ):
            assert "refresh_token" not in parsed

    @pytest.mark.parametrize("per_client", [True, False])
    def test_refresh_token_lifetime(
        self, context, frontend_config, authn_req, per_client, insert_client
    ):
        """
        Test that we can configure the lifetime of the refresh_token globally and per
        client
        """
        lifetime = 100
        usage_rules = {}
        if per_client:
            usage_rules = {
                "token_usage_rules": {"refresh_token": {"expires_in": lifetime}}
            }
        else:
            frontend_config["refresh_token_lifetime"] = lifetime
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["refresh_token"])["grant"]

        assert grant.usage_rules["refresh_token"]["expires_in"] == lifetime
        token = grant.get_token(parsed["refresh_token"])
        assert token.expires_at - token.issued_at == lifetime
        assert token.is_active()

    @pytest.mark.parametrize("per_client", [True, False])
    def test_refresh_token_no_lifetime(
        self, context, frontend_config, authn_req, per_client, insert_client
    ):
        """
        Test that we can configure the lifetime of the refresh_token to never
        expire
        """
        lifetime = 0
        usage_rules = {}
        if per_client:
            usage_rules = {"token_usage_rules": {"refresh_token": {"expires_in": 0}}}
        else:
            frontend_config["refresh_token_lifetime"] = lifetime
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["refresh_token"])["grant"]

        assert grant.usage_rules["refresh_token"]["expires_in"] == lifetime
        token = grant.get_token(parsed["refresh_token"])
        # The token should never expire
        assert token.is_active(now=99999999999)

    def test_id_token_lifetime(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        lifetime = 100
        usage_rules = {}
        frontend_config["id_token_lifetime"] = lifetime
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert id_token["exp"] - id_token["iat"] == lifetime

    def test_id_token_add_claims_by_scope(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        frontend_config["id_token_add_claims_by_scope"] = True
        authn_req.pop("claims")
        authn_req["scope"] = "openid email"
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]
        assert id_token["email_verified"] == OIDC_USERS["testuser1"]["email_verified"]

    def test_id_token_add_claims_by_scope_false(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        frontend_config["id_token_add_claims_by_scope"] = False
        authn_req.pop("claims")
        authn_req["scope"] = "openid email"
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert "email" not in id_token
        assert "email_verified" not in id_token

    def test_id_token_per_client_claims_none(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        usage_rules = {"add_claims": {"always": {"id_token": {"given_name": None}}}}
        frontend_config["id_token_enable_claims_per_client"] = True
        authn_req.pop("claims")
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert id_token["given_name"] == OIDC_USERS["testuser1"]["givenName"][0]

    def test_id_token_per_client_claims_essential(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        usage_rules = {
            "add_claims": {"always": {"id_token": {"given_name": {"essential": True}}}}
        }
        frontend_config["id_token_enable_claims_per_client"] = True
        authn_req.pop("claims")
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert id_token["given_name"] == OIDC_USERS["testuser1"]["givenName"][0]

    def test_id_token_per_client_claims_value(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        usage_rules = {
            "add_claims": {
                "always": {
                    "id_token": {
                        "given_name": {"value": OIDC_USERS["testuser1"]["givenName"][0]}
                    }
                }
            }
        }
        frontend_config["id_token_enable_claims_per_client"] = True
        authn_req.pop("claims")
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert id_token["given_name"] == OIDC_USERS["testuser1"]["givenName"][0]

    def test_id_token_per_client_claims_value_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        usage_rules = {
            "add_claims": {
                "always": {"id_token": {"given_name": {"value": "wrong_value"}}}
            }
        }
        frontend_config["id_token_enable_claims_per_client"] = True
        authn_req.pop("claims")
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert "given_name" not in id_token

    def test_id_token_per_client_claims_values(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        usage_rules = {
            "add_claims": {
                "always": {
                    "id_token": {
                        "given_name": {
                            "values": [
                                OIDC_USERS["testuser1"]["givenName"][0],
                                "wrong_value",
                            ]
                        }
                    }
                }
            }
        }
        frontend_config["id_token_enable_claims_per_client"] = True
        authn_req.pop("claims")
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert id_token["given_name"] == OIDC_USERS["testuser1"]["givenName"][0]

    def test_id_token_per_client_claims_values_fail(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we can configure the lifetime of the id_token globally and per
        client
        """
        usage_rules = {
            "add_claims": {
                "always": {"id_token": {"given_name": {"values": ["wrong_value"]}}}
            }
        }
        frontend_config["id_token_enable_claims_per_client"] = True
        authn_req.pop("claims")
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert "given_name" not in id_token

    def test_token_exchange_disabled(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that token exchange can not be done if disabled.
        """
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token = parsed["access_token"]

        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        resp = AccessTokenResponse().deserialize(response.message, "json")
        err_dscr = (
            "Unsupported grant_type: urn:ietf:params:oauth:grant-type:token-exchange"
        )
        assert resp.to_dict() == {
            "error": "invalid_request",
            "error_description": err_dscr,
        }

    def test_token_exchange_enabled_globally_unsupported_per_client(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that token exchange can not be done if disabled.
        """
        frontend_config["grant_types_supported"].append(
            "urn:ietf:params:oauth:grant-type:token-exchange"
        )
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        user_id = "test_user"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"grant_types_supported": ["authorization_code"]},
        )
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token = parsed["access_token"]

        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        resp = AccessTokenResponse().deserialize(response.message, "json")
        err_dscr = (
            "Unsupported grant_type: urn:ietf:params:oauth:grant-type:token-exchange"
        )
        assert resp.to_dict() == {
            "error": "invalid_request",
            "error_description": err_dscr,
        }

    def test_token_exchange_disabled_globally_supported_per_client(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that token exchange can not be done if disabled.
        """
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        user_id = "test_user"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={
                "grant_types_supported": [
                    "authorization_code",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ]
            },
        )
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token = parsed["access_token"]

        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "access_token" in parsed
        assert "expires_in" in parsed
        assert parsed["token_type"] == "Bearer"
        assert (
            parsed["issued_token_type"]
            == "urn:ietf:params:oauth:token-type:access_token"
        )

    def test_token_exchange(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that token can be exchanged for a new one.
        """
        frontend_config["grant_types_supported"].append(
            "urn:ietf:params:oauth:grant-type:token-exchange"
        )
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "access_token" in parsed
        assert "expires_in" in parsed
        assert parsed["token_type"] == "Bearer"
        assert (
            parsed["issued_token_type"]
            == "urn:ietf:params:oauth:token-type:access_token"
        )

    @pytest.mark.parametrize("attr", ["subject_token", "subject_token_type"])
    def test_token_exchange_missing_attributes(
        self, context, frontend_config, authn_req, attr, insert_client
    ):
        """
        Test that token can be exchanged for a new one.
        """
        frontend_config["grant_types_supported"].append(
            "urn:ietf:params:oauth:grant-type:token-exchange"
        )
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        ).to_dict()
        del req[attr]
        context.request = req

        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        err_dscr = f"Missing required attribute '{attr}'"
        assert parsed.to_dict() == {
            "error": "invalid_request",
            "error_description": err_dscr,
        }

    @pytest.mark.parametrize("scopes", ["openid profile email", "openid unknown email"])
    def test_token_exchange_scopes(
        self, context, frontend_config, authn_req, scopes, insert_client
    ):
        """
        Test that token can be exchanged for a new one.
        """
        expected_scopes_supported = ["openid", "profile", "unknown", "email"]
        frontend_config["allowed_scopes"] = expected_scopes_supported
        frontend_config["deny_unknown_scopes"] = True
        frontend_config["grant_types_supported"].append(
            "urn:ietf:params:oauth:grant-type:token-exchange"
        )
        frontend_config["token_exchange_policy"] = {
            "": {
                "function": (
                    "satosa_oidc_frontend.helpers.token_exchange_policies."
                    "validate_token_exchange_policy"
                ),
                "kwargs": {
                    "scope": ["openid", "email"],
                },
            }
        }
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={"allowed_scopes": expected_scopes_supported},
        )
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["prompt"] = "consent"
        authn_req["scope"] = "openid email"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]
        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            scope=scopes,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "access_token" in parsed
        assert "expires_in" in parsed
        assert parsed["token_type"] == "Bearer"
        assert (
            parsed["issued_token_type"]
            == "urn:ietf:params:oauth:token-type:access_token"
        )
        assert set(parsed["scope"]) == set(["openid", "email"])

    def test_token_exchange_change_client_id_token(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that token can be exchanged for a new one.
        """
        frontend_config["id_token_enable_claims_per_client"] = True
        frontend_config["grant_types_supported"].append(
            "urn:ietf:params:oauth:grant-type:token-exchange"
        )
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        usage_rules = {"add_claims": {"always": {"id_token": {"email": None}}}}
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
            extra_metadata=usage_rules,
        )
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req.pop("claims")

        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            requested_token_type="urn:ietf:params:oauth:token-type:id_token",
        ).to_dict()
        credentials = "{}:{}".format("client2", CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")

        assert "access_token" in parsed
        id_token = AuthorizationResponse().from_jwt(
            parsed["access_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert "expires_in" in parsed
        assert parsed["token_type"] == "N_A"
        assert (
            parsed["issued_token_type"] == "urn:ietf:params:oauth:token-type:id_token"
        )
        assert id_token["client_id"] == "client2"
        assert id_token["email"] == OIDC_USERS["testuser1"]["email"]

    def test_token_exchange_change_client_refresh_token(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that token can be exchanged for a new one.
        """
        frontend_config["grant_types_supported"].append(
            "urn:ietf:params:oauth:grant-type:token-exchange"
        )
        frontend_config["userinfo_enable_claims_per_client"] = True
        frontend_config["token_exchange_policy"] = {
            "": {
                "function": (
                    "satosa_oidc_frontend.helpers.token_exchange_policies."
                    "validate_token_exchange_policy"
                ),
                "kwargs": {
                    "scope": ["openid", "profile", "offline_access"],
                },
            }
        }
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        usage_rules = {"add_claims": {"always": {"userinfo": {"email": None}}}}
        insert_client(frontend, authn_req["redirect_uri"])
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
        )
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client3",
            extra_metadata=usage_rules,
        )
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        authn_req.pop("claims")

        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        # Client1 gets an access token
        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        # Give the access token to client2 to exchange it for a refresh token
        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
            scope="openid offline_access",
        ).to_dict()
        credentials = "{}:{}".format("client2", CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")

        assert "access_token" in parsed
        assert "expires_in" in parsed
        assert parsed["token_type"] == "N_A"
        assert (
            parsed["issued_token_type"]
            == "urn:ietf:params:oauth:token-type:refresh_token"
        )

        # Client2 uses the refresh token to get an access token
        refresh_token = parsed["access_token"]

        context.request = RefreshAccessTokenRequest(
            refresh_token=refresh_token
        ).to_dict()
        credentials = "{}:{}".format("client2", CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token_2 = parsed["access_token"]

        # Client2 gives an access token to client3 to exchange it for a refresh token
        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
        ).to_dict()
        credentials = "{}:{}".format("client3", CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        refresh_token = parsed["access_token"]

        # Client3 uses the refresh token to get an access token issued for him, with
        # the claims that are defined for him
        context.request = RefreshAccessTokenRequest(
            refresh_token=refresh_token
        ).to_dict()
        credentials = "{}:{}".format("client3", CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token_3 = parsed["access_token"]

        context.request = {}
        context.request_authorization = "Bearer {}".format(access_token_2)
        response = frontend.handle_userinfo(context)
        userinfo_2 = OpenIDSchema().deserialize(response.message, "json")

        assert "email" not in userinfo_2

        context.request = {}
        context.request_authorization = "Bearer {}".format(access_token_3)
        response = frontend.handle_userinfo(context)
        userinfo_3 = OpenIDSchema().deserialize(response.message, "json")

        assert userinfo_3["email"] == "test@example.com"

    def test_regex_scopes(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        frontend_config["activate_regex_scopes"] = True
        frontend_config["allowed_scopes_regex"] = ["custom_scope_.*"]
        frontend_config["deny_unknown_scopes"] = False

        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["scope"] = "openid custom_scope_1 custom_scope_gasdgas abababa"
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        assert set(json.loads(response.message)["scope"].split()) == set(
            ["openid", "custom_scope_1", "custom_scope_gasdgas"]
        )

    def test_regex_scopes_2(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        frontend_config["activate_regex_scopes"] = True
        frontend_config["allowed_scopes_regex"] = ["custom_scope_.*"]
        frontend_config["deny_unknown_scopes"] = True

        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["scope"] = "openid custom_scope_1 custom_scope_gasdgas"

        context.request = authn_req
        ret = frontend._handle_authn_request(context)

        assert isinstance(ret, InternalData)
        assert set(authn_req["scope"].split()) == set(
            ["openid", "custom_scope_1", "custom_scope_gasdgas"]
        )

    def test_schemes_denylist_redirect_uri(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we get an "aud" claim when getting an access token and resource is in auth_code flow
        """

        frontend_config["schemes_denylist"] = ["javascript", "data", "vbscript"]
        frontend_config["jwt_access_token"] = True

        frontend = create_frontend(frontend_config)
        usage_rules = {"application_type": "native"}
        authn_req["redirect_uri"] = "javascript://[::1]:9999/auth_cb"
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)

        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"

        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "400 Bad Request"
        assert json.loads(http_resp.message) == {
            "error": "invalid_request",
            "error_description": "URIError:Invalid scheme in redirect URI",
            "state": "my_state",
        }

    def test_resource_indicator_client_credentials_no_config(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test resource_indicator support for client credentials
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend_config["enable_resource_indicators"] = True
        frontend = create_frontend(frontend_config)

        insert_client(frontend, authn_req["redirect_uri"], client_id="client1")
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
            # extra_metadata=usage_rules,
        )
        context.request = CCAccessTokenRequest(
            grant_type="client_credentials",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        response = AccessTokenResponse().deserialize(response.message, "json")

        # Access Token
        access_token = AuthorizationResponse().from_jwt(
            response["access_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert "aud" not in access_token

    def test_client_credentials_resource(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we get an "aud" claim when getting an access token and resource is in auth_code flow
        """

        frontend_config["enable_resource_indicators"] = True
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)

        usage_rules = {
            "resource_indicators": {
                "policy": {
                    "function": "idpyoidc.server.oauth2.token_helper.validate_resource_indicators_policy",
                    "kwargs": {"resource_servers_per_client": ["client2"]},
                }
            }
        }
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_client(frontend, authn_req["redirect_uri"], client_id="client2")
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["resource"] = ["client2"]
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]
        access_token = AuthorizationResponse().from_jwt(
            parsed["access_token"], frontend.endpoint_context.keyjar, sender=""
        )
        token = grant.get_token(parsed["access_token"])
        assert "aud" in access_token
        assert "client2" in access_token["aud"]
        assert token.is_active()

    def test_authcode_access_token_multiple_resource(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we get an "aud" claim when getting an access token and resource is in auth_code flow
        """

        frontend_config["enable_resource_indicators"] = True
        frontend_config["jwt_access_token"] = True

        usage_rules = {
            "resource_indicators": {
                "policy": {
                    "function": "idpyoidc.server.oauth2.token_helper.validate_resource_indicators_policy",
                    "kwargs": {"resource_servers_per_client": ["client2", "client3"]},
                }
            }
        }
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_client(frontend, authn_req["redirect_uri"], client_id="client2")
        insert_client(frontend, authn_req["redirect_uri"], client_id="client3")
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["resource"] = ["client2", "client3"]
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]
        access_token = AuthorizationResponse().from_jwt(
            parsed["access_token"], frontend.endpoint_context.keyjar, sender=""
        )
        token = grant.get_token(parsed["access_token"])
        assert "aud" in access_token
        assert "client2" in access_token["aud"]
        assert "client3" in access_token["aud"]
        assert token.is_active()

    def test_authcode_access_token_multiple_resource_only_itself_valid(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that we get an "aud" claim when getting an access token and resource is in auth_code flow
        """

        frontend_config["enable_resource_indicators"] = True
        frontend_config["jwt_access_token"] = True

        usage_rules = {
            "resource_indicators": {
                "policy": {
                    "function": "idpyoidc.server.oauth2.token_helper.validate_resource_indicators_policy",
                    "kwargs": {"resource_servers_per_client": ["client1", "client13"]},
                }
            }
        }
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_client(frontend, authn_req["redirect_uri"], client_id="client3")
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["resource"] = ["client1", "client13"]
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        assert http_resp.status == "400 Bad Request"
        assert json.loads(http_resp.message) == {
            "error": "invalid_target",
            "error_description": "Invalid resource requested by client client1",
        }

    @pytest.mark.parametrize(
        "resource", ["client2", ["client2", "client3"], ["client2", "client4"]]
    )
    def test_resource_indicator_client_credentials(
        self, context, frontend_config, authn_req, resource, insert_client
    ):
        """
        Test resource_indicator support for client credentials
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend_config["enable_resource_indicators"] = True
        frontend = create_frontend(frontend_config)
        usage_rules = {
            "resource_indicators": {
                "policy": {
                    "function": "idpyoidc.server.oauth2.authorization.validate_resource_indicators_policy",
                    "kwargs": {"resource_servers_per_client": ["client2", "client3"]},
                }
            }
        }

        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client1",
            extra_metadata=usage_rules,
        )
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
            # extra_metadata=usage_rules,
        )
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client3",
            # extra_metadata=usage_rules,
        )
        context.request = CCAccessTokenRequest(
            grant_type="client_credentials", resource=resource, scope="openid"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        if "client4" in resource:
            assert json.loads(response.message) == {
                "error": "invalid_target",
                "error_description": "One or more invalid resources requested by client client1",
            }
        else:
            response = AccessTokenResponse().deserialize(response.message, "json")

            # Access Token
            access_token = AuthorizationResponse().from_jwt(
                response["access_token"], frontend.endpoint_context.keyjar, sender=""
            )

            assert "client2" in access_token["aud"]
            assert "client1" not in access_token["aud"]
            if "client3" in resource:
                assert "client3" in access_token["aud"]

    @pytest.mark.parametrize("resource", ["client1", ["client1", "client3"]])
    def test_resource_indicator_client_credentials_resource_param_itself(
        self, context, frontend_config, authn_req, resource, insert_client
    ):
        """
        Test resource_indicator support for client credentials
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend_config["enable_resource_indicators"] = True
        frontend = create_frontend(frontend_config)
        usage_rules = {
            "resource_indicators": {
                "policy": {
                    "function": "idpyoidc.server.oauth2.authorization.validate_resource_indicators_policy",
                    "kwargs": {"resource_servers_per_client": ["client2"]},
                }
            }
        }

        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client1",
            extra_metadata=usage_rules,
        )
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
            # extra_metadata=usage_rules,
        )
        context.request = CCAccessTokenRequest(
            grant_type="client_credentials", resource=resource, scope="openid"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        if "client3" in resource:
            assert json.loads(response.message) == {
                "error": "invalid_target",
                "error_description": "One or more invalid resources requested by client client1",
            }
        else:
            response = AccessTokenResponse().deserialize(response.message, "json")
            # Access Token
            access_token = AuthorizationResponse().from_jwt(
                response["access_token"], frontend.endpoint_context.keyjar, sender=""
            )
            assert "client1" in access_token["aud"]

    @pytest.mark.parametrize("resource", ["client1", ["client1", "client2"]])
    def test_resource_indicator_client_credentials_no_config_resource_itself(
        self, context, frontend_config, authn_req, resource, insert_client
    ):
        """
        Test resource_indicator support for client credentials
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend_config["enable_resource_indicators"] = True
        frontend = create_frontend(frontend_config)

        insert_client(frontend, authn_req["redirect_uri"], client_id="client1")
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
            # extra_metadata=usage_rules,
        )
        context.request = CCAccessTokenRequest(
            grant_type="client_credentials", resource=resource
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        if "client2" in resource:
            assert json.loads(response.message) == {
                "error": "invalid_target",
                "error_description": "One or more invalid resources requested by client client1",
            }
        else:
            response = AccessTokenResponse().deserialize(response.message, "json")
            # Access Token
            access_token = AuthorizationResponse().from_jwt(
                response["access_token"], frontend.endpoint_context.keyjar, sender=""
            )

            assert "aud" in access_token
            assert "client1" in access_token["aud"]

    @pytest.mark.parametrize("resource", ["client3", ["client3", "client4"]])
    def test_resource_indicator_client_credentials_config_resource_unknown(
        self, context, frontend_config, authn_req, resource, insert_client
    ):
        """
        Test resource_indicator support for client credentials
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend_config["enable_resource_indicators"] = True
        frontend = create_frontend(frontend_config)

        usage_rules = {
            "resource_indicators": {
                "policy": {
                    "function": "idpyoidc.server.oauth2.authorization.validate_resource_indicators_policy",
                    "kwargs": {"resource_servers_per_client": ["client2"]},
                }
            }
        }
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client1",
            extra_metadata=usage_rules,
        )
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
            # extra_metadata=usage_rules,
        )
        context.request = CCAccessTokenRequest(
            grant_type="client_credentials", resource=resource
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        assert json.loads(response.message) == {
            "error": "invalid_target",
            "error_description": "One or more invalid resources requested by client client1",
        }

    def test_client_credentials(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token endpoint.
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])

        context.request = CCAccessTokenRequest(
            grant_type="client_credentials"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]

    @pytest.mark.parametrize("claim_name", ["entitlements", "claims"])
    def test_apply_policy_client_credentials(
        self, context, frontend_config, authn_req, claim_name, insert_client
    ):
        """
        Test policy application to client credentials grant
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)
        extra_metadata = {}
        extra_metadata["allowed_scopes"] = [
            "openid",
            "email",
            "offline_access",
            "eduperson",
            "entitlements",
            "urn:geant:domain.tld:res:res1:act:admin",
            "urn:geant:domain.tld:res:res1:act:viewer",
            "urn:geant:domain.tld:res:res2:act:viewer",
        ]

        extra_metadata["claim_rules"] = {
            "allowed_values": [
                "urn:geant:domain\.tld:res:res1:act:(admin|viewer)",
                "urn:geant:domain.tld:res:res2:act:viewer",
            ],
            "claim_name": claim_name,
            "require_scopes": ["entitlements"],
        }

        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client1",
            extra_metadata=extra_metadata,
        )

        context.request = CCAccessTokenRequest(
            grant_type="client_credentials",
            scope="openid offline_access entitlements urn:geant:domain.tld:res:res2:act:viewer urn:geant:domain.tld:res:res1:act:admin",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        access_token = parsed["access_token"]

        assert access_token

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert intro_resp
        assert claim_name in intro_resp
        assert "urn:geant:domain.tld:res:res1:act:admin" in intro_resp[claim_name]
        assert "urn:geant:domain.tld:res:res2:act:viewer" in intro_resp[claim_name]

    def test_client_credentials_introspection(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token endpoint.
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend = create_frontend(frontend_config)

        insert_client(frontend, authn_req["redirect_uri"])
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        context.request = CCAccessTokenRequest(
            grant_type="client_credentials"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        attributes = frontend.converter.from_internal(
            "openid", internal_response.attributes
        )
        sub = attributes.get("sub", [None])[0]

        assert intro_resp["active"] is True
        assert intro_resp["client_id"] == authn_req["client_id"]
        assert intro_resp["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert intro_resp["token_type"] == "Bearer"
        assert "iat" in intro_resp
        assert "exp" in intro_resp

    def test_token_revocation(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test token revocation.
        """
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        context.request_method = "POST"
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token = parsed["access_token"]
        grant = frontend._load_session_from_token(access_token)["grant"]
        token = grant.get_token(access_token)
        assert token.revoked is False

        context.request = TokenRevocationRequest(
            token=access_token,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token_revocation(context)
        assert response.message == "OK"
        grant = frontend._load_session_from_token(access_token)["grant"]
        token = grant.get_token(access_token)
        assert token.revoked

    def test_token_revocation_bearer(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token revocation using bearer authentication.
        """
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        context.request_method = "POST"
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token = parsed["access_token"]
        grant = frontend._load_session_from_token(access_token)["grant"]
        token = grant.get_token(access_token)
        assert token.revoked is False

        context.request = TokenRevocationRequest(
            token=access_token,
        ).to_dict()
        context.request_method = "POST"
        context.request_authorization = "Bearer {}".format(access_token)

        response = frontend.handle_token_revocation(context)
        assert response.message == "OK"
        grant = frontend._load_session_from_token(access_token)["grant"]
        token = grant.get_token(access_token)
        assert token.revoked

    def test_token_revocation_unsupported_token_type(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token revocation.
        """
        frontend_config["revocation_supported_token_types"] = ["refresh_token"]
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        context.request_method = "POST"
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token = parsed["access_token"]

        context.request = TokenRevocationRequest(
            token=access_token,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token_revocation(context)
        assert response.message != "OK"

    def test_token_revocation_unsupported_token_type_per_client(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token revocation per client.
        """
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        user_id = "test_user"
        token_revocation = {"token_types_supported": ["refresh_token"]}
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata=dict(token_revocation=token_revocation),
        )
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        context.request_method = "POST"
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        access_token = parsed["access_token"]

        context.request = TokenRevocationRequest(
            token=access_token,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token_revocation(context)
        assert response.message != "OK"

    def test_resource_indicators_token_endpoint(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test token endpoint.
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend_config["enable_resource_indicators"] = True
        frontend_config["access_token_resource_servers_per_client"] = {
            "client1": ["client2"],
            "client2": ["client1"],
        }
        frontend_config["authorization_resource_servers_per_client"] = frontend_config[
            "access_token_resource_servers_per_client"
        ]
        frontend = create_frontend(frontend_config)

        user_id = "test_user"
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            extra_metadata={
                "allowed_scopes": ["openid", "email", "offline_access", "eduperson"]
            },
        )
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
            extra_metadata={
                "allowed_scopes": ["openid", "email", "offline_access", "eduperson"]
            },
        )

        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["resource"] = ["client2"]
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert parsed["access_token"]
        assert parsed["expires_in"] == token_lifetime
        assert parsed["id_token"]
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )
        assert "email" in id_token
        assert "email_verified" not in id_token


class TestOpenIDConnectFrontendDB(TestOpenIDConnectFrontend):
    @pytest.fixture
    def frontend_config(self):
        config = {
            "response_types_supported": response_types_supported,
            "enable_registration_endpoint": True,
            "enable_introspection_endpoint": True,
            "enable_revocation_endpoint": True,
            "allowed_scopes": ["openid", "email", "offline_access"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "response_modes_supported": ["query", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "jwks": JWKS,
            "token_session_encryption_password": "password",
            "db_uri": "sqlite:///:memory:",
            "registration_authn": ["public"],
            "scopes_supported": ["openid", "email", "offline_access", "eduperson"],
            "client_db_handler_class_path": "satosa_oidc_frontend.frontend.ClientDB",
            "client_db_enable_import": True,
        }

        return config

    @pytest.fixture
    def frontend_config_extra_scopes(self):
        config = {
            "response_types_supported": response_types_supported,
            "enable_registration_endpoint": True,
            "enable_introspection_endpoint": True,
            "enable_revocation_endpoint": True,
            "allowed_scopes": ["openid", "email", "offline_access", "eduperson"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "response_modes_supported": ["query", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "jwks": JWKS,
            "token_session_encryption_password": "password",
            "scopes_to_claims": EXTRA_SCOPES,
            "db_uri": "sqlite:///:memory:",
            "scopes_supported": ["openid", "email", "offline_access", "eduperson"],
            "client_db_handler_class_path": "satosa_oidc_frontend.frontend.ClientDB",
            "client_db_enable_import": True,
        }

        return config

    def test_token_req_after_restart(
        self, context, frontend_config, authn_req, insert_client
    ):
        lifetime = 100
        usage_rules = {}
        frontend_config["refresh_token_lifetime"] = lifetime
        frontend1 = create_frontend(frontend_config)
        frontend2 = create_frontend(frontend_config)
        insert_client(frontend1, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_userinfo(frontend1, "user_id")

        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend1, authn_req)

        http_resp = frontend1.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend2.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend2._load_session_from_token(parsed["refresh_token"])["grant"]

        assert grant.usage_rules["refresh_token"]["expires_in"] == lifetime
        token = grant.get_token(parsed["refresh_token"])
        assert token.expires_at - token.issued_at == lifetime
        assert token.is_active()

    def test_userinfo_req_after_restart(
        self, context, frontend_config, authn_req, insert_client
    ):
        client_claims = {"add_claims": {"by_scope": {"userinfo": True}}}
        frontend1 = create_frontend(frontend_config)
        frontend2 = create_frontend(frontend_config)
        insert_client(
            frontend1, authn_req["redirect_uri"], extra_metadata=client_claims
        )
        insert_userinfo(frontend1, "user_id")
        insert_client(
            frontend2, authn_req["redirect_uri"], extra_metadata=client_claims
        )
        insert_userinfo(frontend2, "user_id")

        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access email"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend1, authn_req)

        http_resp = frontend1.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)
        response = frontend1.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")

        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        context.request = {}
        response = frontend1.handle_userinfo(context)
        assert json.loads(response.message) == {
            "sub": "one!for!all",
            "email": "test@example.com",
            "email_verified": True,
        }
        context.request_authorization = "Bearer {}".format(parsed["access_token"])
        context.request = {}
        response = frontend2.handle_userinfo(context)
        assert json.loads(response.message) == {
            "sub": "one!for!all",
            "email": "test@example.com",
            "email_verified": True,
        }


class TestOpenIDConnectFrontendDBHashedSecret(TestOpenIDConnectFrontend):
    @pytest.fixture
    def frontend_config(self):
        config = {
            "response_types_supported": response_types_supported,
            "enable_registration_endpoint": True,
            "enable_introspection_endpoint": True,
            "enable_revocation_endpoint": True,
            "allowed_scopes": ["openid", "email", "offline_access"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "response_modes_supported": ["query", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "jwks": JWKS,
            "token_session_encryption_password": "password",
            "db_uri": "sqlite:///:memory:",
            "registration_authn": ["public"],
            "scopes_supported": ["openid", "email", "offline_access", "eduperson"],
            "client_db_enable_import": True,
            "client_db_handler_class_path": "satosa_oidc_frontend.frontend.ClientDBHashedSecrets",
            "client_db_enable_import": True,
            "client_db_enable_secret_hashing_on_import": True,
        }

        return config

    @pytest.fixture
    def frontend_config_extra_scopes(self, frontend_config):
        config = frontend_config | {
            "allowed_scopes": ["openid", "email", "offline_access", "eduperson"],
            "scopes_to_claims": EXTRA_SCOPES,
        }

        return config


class TestRemoteIntrospection(object):
    @pytest.fixture
    def jwt_no_iss(self):
        """
        JWT with payload:
        {
          "sub": "1234567890",
          "name": "John Doe",
          "iat": 1516239022
        }
        """
        return (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw"
            "IiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSM"
            "eKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )

    @pytest.fixture
    def jwt_unknown_iss(self):
        """
        JWT with payload:
        {
          "sub": "1234567890",
          "name": "John Doe",
          "iat": 1516239022,
          "iss": "https://unknown.example.com/"
        }

        """
        return (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw"
            "IiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJod"
            "HRwczovL3Vua25vd24uZXhhbXBsZS5jb20vIn0.Sv0N2VWgCXx0MvnmqjlnG3"
            "UOB0tJhynh6L5eHXs_BGE"
        )

    @pytest.fixture
    def jwt_known_iss(self):
        """
        JWT with payload:
        {
          "sub": "1234567890",
          "name": "John Doe",
          "iat": 1516239022,
          "iss": "https://provider.example.com/"
        }
        """
        return (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw"
            "IiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJod"
            "HRwczovL3Byb3ZpZGVyLmV4YW1wbGUuY29tLyJ9.XZO0SbmAbYGQtkG65q3JG"
            "eVBC7SODhsAGhZIbkzGE2c"
        )

    @pytest.fixture
    def remote_introspection_config(self):
        return {
            "https://provider.example.com/": {
                "client_id": "test",
                "client_secret": "secr3t",
                "endpoints": ["https://provider.example.com/introspect"],
            },
            "": {
                "client_id": "test",
                "client_secret": "hunter2",
                "endpoints": [
                    "https://provider2.example.com/introspect",
                    "https://provider2.example.com/introspect2",
                ],
            },
        }

    @pytest.fixture
    def frontend_config(self, remote_introspection_config):
        config = {
            "response_types_supported": response_types_supported,
            "enable_registration_endpoint": True,
            "enable_introspection_endpoint": True,
            "allowed_scopes": ["openid", "email"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "response_modes_supported": ["query", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "jwks": JWKS,
            "token_session_encryption_password": "password",
            "introspection_post_process_hooks": [
                {
                    "class": "satosa_oidc_frontend.RemoteIntrospection",
                    "kwargs": {
                        "remote_introspection_providers": remote_introspection_config
                    },
                },
                {
                    "class": "satosa_oidc_frontend.RemoteDataProvider",
                    "kwargs": {
                        "remote_endpoints": [
                            {
                                "wrap_claim_name": "my_custom_claim",
                                "ignore_api_error": False,
                                "api_url": "https://provider2.example.com/userinfo",
                                "api_username": "foo",
                                "api_password": "bar",
                                "api_timeout": 60,
                                "api_retries": 3,
                            }
                        ]
                    },
                },
            ],
        }

        return config

    @responses.activate
    def test_remote_introspection_timeout(
        self,
        context,
        authn_req,
        frontend_config,
        remote_introspection_config,
        insert_client,
    ):
        """
        Test that the remote introspection request handles
        remote timeouts correctly.
        """
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        remote_intro_provider = remote_introspection_config[""]

        responses.add(responses.POST, body=Timeout(), url="")

        introspection_request = TokenIntrospectionRequest(token="tokentokentoken")

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)
        remote_creds = create_auth(
            remote_intro_provider["client_id"], remote_intro_provider["client_secret"]
        )
        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert not intro_resp["active"]
        assert len(responses.calls) == 2
        for i in (0, 1):
            assert (
                responses.calls[i].request.url == remote_intro_provider["endpoints"][i]
            )
            assert responses.calls[i].request.headers["Authorization"] == remote_creds
            assert responses.calls[i].request.body == "token=tokentokentoken"

    @responses.activate
    def test_remote_introspection_unknown_iss_no_fallback(
        self,
        context,
        frontend_config,
        authn_req,
        jwt_unknown_iss,
        remote_introspection_config,
        insert_client,
    ):
        """
        Test that no remote introspection request happens
        when finding unknown issuer and have no fallback
        remote providers configured.
        """

        del remote_introspection_config[""]
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        introspection_request = TokenIntrospectionRequest(token=jwt_unknown_iss)

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)

        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert not intro_resp["active"]
        assert not len(responses.calls)

    @responses.activate
    def test_remote_introspection_issuer_credentials_missing_in_config(
        self, context, frontend_config, authn_req
    ):
        """
        Test that the frontend fails to be created when provider credentials
        or endpoints are missing from the config.
        """
        _config = dict(
            frontend_config["introspection_post_process_hooks"][0]["kwargs"][
                "remote_introspection_providers"
            ]
        )
        _frontend_config = dict(frontend_config)
        _frontend_config["introspection_post_process_hooks"][0]["kwargs"][
            "remote_introspection_providers"
        ] = _config
        del _config[""]["client_id"]
        with pytest.raises(SATOSAConfigurationError) as e:
            create_frontend(dict(_frontend_config))
        assert e.value.args[0] == "Missing info in remote_introspection_providers"

        _config = dict(
            frontend_config["introspection_post_process_hooks"][0]["kwargs"][
                "remote_introspection_providers"
            ]
        )
        del _config[""]["client_secret"]
        _frontend_config = dict(frontend_config)
        _frontend_config["introspection_post_process_hooks"][0]["kwargs"][
            "remote_introspection_providers"
        ] = _config
        with pytest.raises(SATOSAConfigurationError) as e:
            create_frontend(_frontend_config)
        assert e.value.args[0] == "Missing info in remote_introspection_providers"

        _config = dict(
            frontend_config["introspection_post_process_hooks"][0]["kwargs"][
                "remote_introspection_providers"
            ]
        )
        del _config[""]["endpoints"]
        _frontend_config = dict(frontend_config)
        _frontend_config["introspection_post_process_hooks"][0]["kwargs"][
            "remote_introspection_providers"
        ] = _config
        with pytest.raises(SATOSAConfigurationError) as e:
            create_frontend(_frontend_config)
        assert e.value.args[0] == "Missing info in remote_introspection_providers"

        _config = dict(
            frontend_config["introspection_post_process_hooks"][0]["kwargs"][
                "remote_introspection_providers"
            ]
        )
        _config[""]["endpoints"] = []
        _frontend_config = dict(frontend_config)
        _frontend_config["introspection_post_process_hooks"][0]["kwargs"][
            "remote_introspection_providers"
        ] = _config
        with pytest.raises(SATOSAConfigurationError) as e:
            create_frontend(_frontend_config)
        assert e.value.args[0] == "Missing info in remote_introspection_providers"

    @responses.activate
    def test_remote_introspection_malformed_request(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that a malformed introspection request will not be sent remotely.
        """
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        introspection_request = TokenIntrospectionRequest(token="tokentokentoken")

        introspection_request["tokean"] = introspection_request["token"]
        del introspection_request["token"]

        context.request = introspection_request.to_dict()

        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "400 Bad Request"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "error" in intro_resp
        assert len(responses.calls) == 0

    @responses.activate
    def test_remote_introspection_active_locally(
        self, context, frontend_config, authn_req, insert_client
    ):
        """
        Test that a successful introspection locally will not be sent remotely.
        """
        user_id = "test_user"
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )
        assert "active" in intro_resp
        assert intro_resp["active"] is True
        assert len(responses.calls) == 0

    @responses.activate
    def test_remote_introspection_no_JWT(
        self,
        context,
        frontend_config,
        authn_req,
        remote_introspection_config,
        insert_client,
    ):
        """
        Test that an introspection request with a non-JWT token will be tried
        on the fallback provider.
        """
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        remote_intro_provider = remote_introspection_config[""]
        remote_response_json = {"active": True, "sub": "subsubsub"}

        responses.add(
            responses.POST,
            remote_intro_provider["endpoints"][0],
            json=remote_response_json,
            status=200,
        )

        introspection_request = TokenIntrospectionRequest(token="tokentokentoken")

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)
        remote_creds = create_auth(
            remote_intro_provider["client_id"], remote_intro_provider["client_secret"]
        )
        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert intro_resp["active"]
        assert responses.calls[0].request.url == remote_intro_provider["endpoints"][0]
        assert len(responses.calls) == 1
        assert responses.calls[0].request.headers["Authorization"] == remote_creds
        assert responses.calls[0].request.body == "token=tokentokentoken"
        assert "sub" in intro_resp
        assert intro_resp["sub"] == "subsubsub"

    @responses.activate
    def test_remote_introspection_with_remote_data_provider(
        self,
        context,
        frontend_config,
        authn_req,
        remote_introspection_config,
        insert_client,
    ):
        """
        Test that an introspection request with a non-JWT token will be tried
        on the fallback provider.
        """
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        remote_intro_provider = remote_introspection_config[""]
        remote_response_json = {"active": True, "sub": "subsubsub"}
        remote_response_userinfo = {"claims": ["claim1", "claim2"]}
        responses.add(
            responses.POST,
            remote_intro_provider["endpoints"][0],
            json=remote_response_json,
            status=200,
        )

        responses.add(
            responses.POST,
            "https://provider2.example.com/userinfo",
            json=remote_response_userinfo,
            status=200,
        )

        introspection_request = TokenIntrospectionRequest(token="tokentokentoken")

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)
        remote_creds = create_auth(
            remote_intro_provider["client_id"], remote_intro_provider["client_secret"]
        )
        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert intro_resp["active"]
        assert responses.calls[0].request.url == remote_intro_provider["endpoints"][0]
        assert responses.calls[0].request.headers["Authorization"] == remote_creds
        assert responses.calls[0].request.body == "token=tokentokentoken"
        assert "sub" in intro_resp
        assert intro_resp["sub"] == "subsubsub"
        assert "my_custom_claim" in intro_resp

    @responses.activate
    def test_remote_introspection_no_iss_in_JWT(
        self,
        context,
        frontend_config,
        authn_req,
        remote_introspection_config,
        jwt_no_iss,
        insert_client,
    ):
        """
        Test that an introspection request with a JWT without an issuer will be
        tried on the fallback provider.
        """
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        remote_intro_provider = remote_introspection_config[""]
        remote_response_json = {"active": True, "sub": "subsubsub"}

        responses.add(
            responses.POST,
            remote_intro_provider["endpoints"][0],
            json=remote_response_json,
            status=200,
        )

        introspection_request = TokenIntrospectionRequest(token=jwt_no_iss)

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)
        remote_creds = create_auth(
            remote_intro_provider["client_id"], remote_intro_provider["client_secret"]
        )

        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert intro_resp["active"]
        assert responses.calls[0].request.url == remote_intro_provider["endpoints"][0]
        assert len(responses.calls) == 1
        assert responses.calls[0].request.headers["Authorization"] == remote_creds
        assert responses.calls[0].request.body == f"token={jwt_no_iss}"
        assert "sub" in intro_resp
        assert intro_resp["sub"] == "subsubsub"

    @responses.activate
    def test_remote_introspection_unknown_iss_in_JWT(
        self,
        context,
        frontend_config,
        authn_req,
        jwt_unknown_iss,
        remote_introspection_config,
        insert_client,
    ):
        """
        Test that an introspection request with a JWT with an unknown issuer
        will be tried on the fallback provider.
        """
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        remote_intro_provider = remote_introspection_config[""]
        remote_response_json = {"active": True, "sub": "subsubsub"}

        responses.add(
            responses.POST,
            remote_intro_provider["endpoints"][0],
            json=remote_response_json,
            status=200,
        )

        introspection_request = TokenIntrospectionRequest(token=jwt_unknown_iss)

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)
        remote_creds = create_auth(
            remote_intro_provider["client_id"], remote_intro_provider["client_secret"]
        )

        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert intro_resp["active"]
        assert responses.calls[0].request.url == remote_intro_provider["endpoints"][0]
        assert len(responses.calls) == 1
        assert responses.calls[0].request.headers["Authorization"] == remote_creds
        assert responses.calls[0].request.body == f"token={jwt_unknown_iss}"
        assert "sub" in intro_resp
        assert intro_resp["sub"] == "subsubsub"

    @pytest.mark.parametrize("is_active_in_remote", [True, False])
    @responses.activate
    def test_remote_introspection_found_iss_in_JWT(
        self,
        context,
        frontend_config,
        authn_req,
        is_active_in_remote,
        remote_introspection_config,
        jwt_known_iss,
        insert_client,
    ):
        """
        Test that an introspection request with a JWT with a known issuer
        will be tried on the correct provider and succeed or fail.
        """
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        remote_intro_provider = remote_introspection_config[
            "https://provider.example.com/"
        ]
        remote_response_json = {"active": is_active_in_remote}

        if is_active_in_remote:
            remote_response_json.update({"sub": "subsubsub"})

        responses.add(
            responses.POST,
            remote_intro_provider["endpoints"][0],
            json=remote_response_json,
            status=200,
        )

        introspection_request = TokenIntrospectionRequest(token=jwt_known_iss)

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)
        remote_creds = create_auth(
            remote_intro_provider["client_id"], remote_intro_provider["client_secret"]
        )

        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert intro_resp["active"] is is_active_in_remote
        assert responses.calls[0].request.url == remote_intro_provider["endpoints"][0]
        assert responses.calls[0].request.headers["Authorization"] == remote_creds
        assert responses.calls[0].request.body == f"token={jwt_known_iss}"
        assert len(responses.calls) == 1
        if is_active_in_remote:
            assert intro_resp["active"]
            assert "sub" in intro_resp
            assert intro_resp["sub"] == "subsubsub"

    @responses.activate
    def test_remote_introspection_not_active_on_multiple(
        self,
        context,
        authn_req,
        frontend_config,
        remote_introspection_config,
        insert_client,
    ):
        """
        Test that remote introspection happens and fails predictably when
        remote provider finds the token inactive.
        """
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        remote_intro_provider = remote_introspection_config[""]
        remote_response_json = {"active": False}

        responses.add(responses.POST, json=remote_response_json, status=200, url="")
        introspection_request = TokenIntrospectionRequest(token="tokentokentoken")

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)
        remote_creds = create_auth(
            remote_intro_provider["client_id"], remote_intro_provider["client_secret"]
        )

        introspection_response = frontend.handle_introspection(context)

        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert not intro_resp["active"]
        assert len(responses.calls) == 2
        for i in (0, 1):
            assert (
                responses.calls[i].request.url == remote_intro_provider["endpoints"][i]
            )
            assert responses.calls[i].request.headers["Authorization"] == remote_creds
            assert responses.calls[i].request.body == "token=tokentokentoken"

    @responses.activate
    def test_remote_introspection_active_in_second_endpoint(
        self,
        context,
        frontend_config,
        authn_req,
        remote_introspection_config,
        insert_client,
    ):
        """
        Test that the remote introspection request succeeds when
        only the second endpoint succeeds on the remote provider.
        """
        del frontend_config["introspection_post_process_hooks"][1]
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        frontend.register_endpoints(["test_backend"])

        remote_intro_provider = remote_introspection_config[""]
        remote_response_json = {"active": False}

        responses.add(
            responses.POST,
            remote_intro_provider["endpoints"][0],
            json=remote_response_json,
            status=200,
        )

        remote_response_json.update({"active": True, "sub": "subsubsub"})
        responses.add(
            responses.POST,
            remote_intro_provider["endpoints"][1],
            json=remote_response_json,
            status=200,
        )

        introspection_request = TokenIntrospectionRequest(token="tokentokentoken")

        context.request = introspection_request.to_dict()

        context.request_authorization = create_auth(CLIENT_ID, CLIENT_SECRET)
        remote_creds = create_auth(
            remote_intro_provider["client_id"], remote_intro_provider["client_secret"]
        )

        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert intro_resp["active"]
        assert len(responses.calls) == 2
        for i in (0, 1):
            assert (
                responses.calls[i].request.url == remote_intro_provider["endpoints"][i]
            )
            assert responses.calls[i].request.headers["Authorization"] == remote_creds
            assert responses.calls[i].request.body == "token=tokentokentoken"


class TestAudiencePolicies(object):
    @pytest.fixture
    def audience_policy_config(self):
        return {"client1": {}}

    @pytest.fixture
    def frontend_config(self, audience_policy_config):
        config = {
            "response_types_supported": response_types_supported,
            "enable_registration_endpoint": True,
            "enable_introspection_endpoint": True,
            "allowed_scopes": ["openid", "email", "profile"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "response_modes_supported": ["query", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "jwks": JWKS,
            "token_session_encryption_password": "password",
        }

        return config

    def test_authcode_access_token_resource(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that we get an "aud" claim when getting an access token and resource is in auth_code flow
        """

        frontend_config["enable_audience_policies"] = True
        frontend_config["audience_policies"] = {
            "": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
            "client1": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
        }
        frontend_config["jwt_access_token"] = True
        frontend = create_frontend(frontend_config)

        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"])
        insert_client(frontend, authn_req["redirect_uri"], client_id="client2")
        insert_userinfo(frontend, "user_id")
        authn_req["response_type"] = "code"
        authn_req["resource"] = ["client2"]
        internal_response = setup_for_authn_response(context, frontend, authn_req)

        http_resp = frontend.handle_authn_response(context, internal_response)

        authn_resp = parse_qs(urlparse(http_resp.message).query)

        assert http_resp.status == "302 Found"
        assert "code" in authn_resp

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=authn_resp["code"][0]
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        grant = frontend._load_session_from_token(parsed["access_token"])["grant"]
        access_token = AuthorizationResponse().from_jwt(
            parsed["access_token"], frontend.endpoint_context.keyjar, sender=""
        )
        token = grant.get_token(parsed["access_token"])
        assert token.is_active()

    def test_audience_policies_client_credentials_no_resource(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test resource_indicator support for client credentials
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend_config["enable_audience_policies"] = True
        frontend_config["audience_policies"] = {
            "client1": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                },
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.validateResources",
                },
            ]
        }
        frontend = create_frontend(frontend_config)

        insert_client(frontend, authn_req["redirect_uri"], client_id="client1")

        context.request = CCAccessTokenRequest(
            grant_type="client_credentials", scope="openid"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        response = AccessTokenResponse().deserialize(response.message, "json")
        assert response["error"] == "audience_policy_error"
        assert response["error_description"] == "No resource in the request"

    @pytest.mark.parametrize(
        "resource", ["client2", ["client2", "client3"], ["client2", "client4"]]
    )
    def test_audience_policies_client_credentials_with_resources(
        self,
        context,
        frontend_config,
        authn_req,
        resource,
        insert_client,
    ):
        """
        Test resource_indicator support for client credentials
        """
        token_lifetime = 60 * 60 * 24
        frontend_config["jwt_access_token"] = True
        frontend_config["grant_types_supported"].append("client_credentials")
        frontend_config["access_token_lifetime"] = token_lifetime
        frontend_config["enable_audience_policies"] = True
        frontend_config["audience_policies"] = {
            "": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
            "client1": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                },
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.validateResources",
                },
            ],
        }
        frontend = create_frontend(frontend_config)
        insert_client(frontend, authn_req["redirect_uri"], client_id="client1")
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client2",
            # extra_metadata=usage_rules,
        )
        insert_client(
            frontend,
            authn_req["redirect_uri"],
            client_id="client3",
            # extra_metadata=usage_rules,
        )
        context.request = CCAccessTokenRequest(
            grant_type="client_credentials", resource=resource, scope="openid"
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        response = AccessTokenResponse().deserialize(response.message, "json")

        grant = frontend._load_session_from_token(response["access_token"])["grant"]
        token = grant.get_token(response["access_token"])
        assert token.is_active()

    def test_audience_policies_token_exchange(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that audience policies can be applied when token is being exchanged for a new one.
        """
        frontend_config["grant_types_supported"].append(
            "urn:ietf:params:oauth:grant-type:token-exchange"
        )
        frontend_config["enable_audience_policies"] = True
        frontend_config["audience_policies"] = {
            "": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
            "client1": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
        }
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        context.request = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=access_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)

        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "access_token" in parsed
        assert "expires_in" in parsed
        assert parsed["token_type"] == "Bearer"
        assert (
            parsed["issued_token_type"]
            == "urn:ietf:params:oauth:token-type:access_token"
        )

    def test_audience_policies_handle_introspection(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that audience policies can be applied when token introspection is in place.
        """
        user_id = "test_user"
        frontend_config["enable_audience_policies"] = True
        frontend_config["audience_policies"] = {
            "": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
            "client1": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
        }
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        attributes = frontend.converter.from_internal(
            "openid", internal_response.attributes
        )
        sub = attributes.get("sub", [None])[0]

        assert intro_resp["active"] is True
        assert intro_resp["client_id"] == authn_req["client_id"]
        assert intro_resp["iss"] == "{}/{}".format(BASE_URL, frontend.name)
        assert intro_resp["sub"] == sub
        assert intro_resp["token_type"] == "Bearer"
        assert intro_resp["scope"] == authn_req["scope"]
        assert "iat" in intro_resp
        assert "exp" in intro_resp

    def test_audience_policies_handle_introspection_fail(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that when audience policies fail, the token introspection will return {active: False}
        """
        user_id = "test_user"
        frontend_config["enable_audience_policies"] = True
        frontend_config["audience_policies"] = {
            "": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
            "client1": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.checkIntrospectionFail",
                }
            ],
        }
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert not intro_resp["active"]
        assert not len(responses.calls)

    def test_audience_policies_handle_introspection_resource(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that when audience policies fail, the token introspection will return {active: False}
        """
        user_id = "test_user"
        frontend_config["enable_audience_policies"] = True
        frontend_config["audience_policies"] = {
            "": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
            "client1": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.checkAudienceExist",
                }
            ],
        }
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])
        insert_client(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["resource"] = ["client2", "client3"]
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"],
            code=code,
        ).to_dict()
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        access_token = parsed["access_token"]

        introspection_request = TokenIntrospectionRequest(token=access_token)
        context.request = introspection_request.to_dict()
        introspection_response = frontend.handle_introspection(context)
        assert introspection_response.status == "200 OK"

        intro_resp = TokenIntrospectionResponse().deserialize(
            introspection_response.message, "json"
        )

        assert "active" in intro_resp
        assert intro_resp["active"]

    def test_audience_policies_refresh_token(
        self,
        context,
        frontend_config,
        authn_req,
        insert_client,
    ):
        """
        Test that we can apply audience policies at refresh token.
        """
        frontend_config["id_token_add_claims_by_scope"] = True
        frontend_config["enable_resource_indicators"] = True
        frontend_config["enable_audience_policies"] = True
        frontend_config["audience_policies"] = {
            "": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.simpleLogger",
                }
            ],
            "client1": [
                {
                    "function": "satosa_oidc_frontend.helpers.audience_policies.checkRefreshTokenRequest",
                }
            ],
        }
        frontend = create_frontend(frontend_config)
        usage_rules = {
            "resource_indicators": {
                "policy": {
                    "function": "idpyoidc.server.oauth2.token_helper.validate_resource_indicators_policy",
                    "kwargs": {"resource_servers_per_client": ["client2"]},
                }
            }
        }

        user_id = "test_user"
        insert_client(frontend, authn_req["redirect_uri"], extra_metadata=usage_rules)
        insert_client(frontend, authn_req["redirect_uri"], client_id="client2")
        insert_userinfo(frontend, user_id)
        authn_req["response_type"] = "code"
        authn_req["scope"] = "openid offline_access email"
        authn_req["prompt"] = "consent"
        authn_req.pop("claims")
        authn_req["resource"] = ["client2"]
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        )
        credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
        basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        context.request_authorization = "Basic {}".format(basic_auth)

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert parsed["refresh_token"]
        assert "email" in id_token

        context.request = RefreshAccessTokenRequest(
            refresh_token=parsed["refresh_token"], scope="openid offline_access"
        )

        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        id_token_2 = AuthorizationResponse().from_jwt(
            parsed["id_token"], frontend.endpoint_context.keyjar, sender=""
        )

        assert "access_token" in parsed
        assert "refresh_token" in parsed
        assert "id_token" in parsed
        assert "email" not in id_token_2
        assert set(parsed["scope"]) == set(["openid", "offline_access"])


class TestRemoteDataProviderInfo(object):
    @pytest.fixture
    def remote_data_provider_config(self):
        return [
            {
                "require_scopes": ["openid"],
                "wrap_claim_name": "my_custom_claim",
                "ignore_api_error": True,
                "api_url": "https://provider2.example.com/userinfo",
                "api_username": "foo",
                "api_password": "bar",
                "api_timeout": 60,
                "api_retries": 3,
            },
            {
                "require_scopes": ["openid"],
                "wrap_claim_name": "another_custom_claim",
                "ignore_api_error": True,
                "api_url": "https://provider3.example.com/userinfo",
                "api_username": "foo",
                "api_password": "bar",
                "api_timeout": 60,
                "api_retries": 3,
            },
        ]

    @pytest.fixture
    def frontend_config(self, remote_data_provider_config):
        config = {
            "response_types_supported": response_types_supported,
            "enable_registration_endpoint": True,
            "enable_introspection_endpoint": True,
            "allowed_scopes": ["openid", "email", "profile"],
            "subject_types_supported": ["pairwise"],
            "claim_types_supported": ["normal"],
            "response_modes_supported": ["query", "form_post"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "jwks": JWKS,
            "token_session_encryption_password": "password",
            "userinfo_post_process_hooks": [
                {
                    "class": "satosa_oidc_frontend.RemoteDataProvider",
                    "kwargs": {"remote_endpoints": remote_data_provider_config},
                }
            ],
        }

        return config

    @pytest.fixture
    def userinfo_flow(
        self,
        context,
        authn_req,
        frontend_config,
        insert_client,
    ):
        def _userinfo_flow(fail = False):
            frontend_config["jwt_access_token"] = True
            # Setup frontend with token exchange support to test (fail = True)
            frontend_config["grant_types_supported"].extend([
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ])
            frontend = create_frontend(frontend_config)
            insert_client(frontend, authn_req["redirect_uri"])
            # frontend.register_endpoints(["test_backend"])

            # authentication request
            authn_req["response_type"] = "code id_token token"
            custom_authn_req = AuthorizationRequest(
                redirect_uri=authn_req["redirect_uri"],
                client_id=authn_req["client_id"],
                response_type=authn_req["response_type"],
                scope="eduperson openid offline_access",
                state="state",
                nonce="nonce",
                prompt="consent"
            )

            context.request = dict(parse_qsl(custom_authn_req.to_urlencoded()))
            frontend.handle_authn_request(context)
            internal_response = setup_for_authn_response(
                context, frontend, context.request
            )
            http_response = frontend.handle_authn_response(context, internal_response)

            # Tokens request
            code = parse_qs(urlparse(http_response.message).fragment)["code"][0]
            context.request = AccessTokenRequest(
                redirect_uri=custom_authn_req["redirect_uri"], code=code
            ).to_dict()
            credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
            basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
            context.request_authorization = "Basic {}".format(basic_auth)
            response = frontend.handle_token(context)
            parsed = AccessTokenResponse().deserialize(response.message, "json")

            if fail:
                # remove openid from scope in order to fail
                context.request = TokenExchangeRequest(
                    grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
                    subject_token=parsed["refresh_token"],
                    scope="eduperson",
                    subject_token_type="urn:ietf:params:oauth:token-type:refresh_token",
                ).to_dict()
                credentials = "{}:{}".format(CLIENT_ID, CLIENT_SECRET)
                basic_auth = urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
                context.request_authorization = "Basic {}".format(basic_auth)
                response = frontend.handle_token(context)
                parsed = AccessTokenResponse().deserialize(response.message, "json")

                assert "access_token" in parsed
                assert "expires_in" in parsed
                assert parsed["token_type"] == "Bearer"
                assert (
                    parsed["issued_token_type"]
                    == "urn:ietf:params:oauth:token-type:access_token"
                )
            
            # userinfo request
            context.request_authorization = "Bearer {}".format(parsed["access_token"])
            http_response = frontend.handle_userinfo(context)
            return http_response

        return _userinfo_flow

    @responses.activate
    def test_remote_data_provider(
        self,
        remote_data_provider_config,
        userinfo_flow,
    ):
        """
        Test that the remote data provider request is handled properly.
        """
        remote_data_provider_endpoint = remote_data_provider_config[0]

        mock_response_json = {"claims": ["claim1", "claim2"]}
        with requests_mock.Mocker() as mock:
            mock_url = "https://provider2.example.com/userinfo"
            mock.register_uri(
                "POST", mock_url, json=mock_response_json, status_code=200
            )

            resp = userinfo_flow()
            payload = json.loads(resp.message)
            assert resp.status == "200 OK"
            assert "sub" in payload
            assert remote_data_provider_endpoint["wrap_claim_name"] in payload
            assert "claims" in payload[remote_data_provider_endpoint["wrap_claim_name"]]

    @responses.activate
    def test_remote_data_provider_fail(
        self, 
        remote_data_provider_config, 
        context, 
        authn_req,
        frontend_config,
        userinfo_flow
    ):
        """
        Test that the remote data provider request will fail gracefully when 
        will exchange a refresh token without having openid scope.
        """
        remote_data_provider_endpoint = remote_data_provider_config[0]

        mock_response_json = {'claims': ['claim1', 'claim2']}
        with requests_mock.Mocker() as mock:
            mock_url = 'https://provider2.example.com/userinfo'
            mock.register_uri('POST', mock_url, json=mock_response_json, status_code=200)

            resp = userinfo_flow(fail = True)
            assert isinstance(resp, BadRequest)
            assert resp.message.to_dict() == {
                "error": "invalid_token",
                "error_description": "Invalid Token",
            }
            assert resp.status == "400 Bad Request"
       
    @responses.activate
    def test_multiple_remote_data_provider(
        self,
        remote_data_provider_config,
        userinfo_flow,
    ):
        """
        Test that the multiple remote data provider request is handled properly.
        """

        mock_response_json_endpoint1 = {"claims": ["claim1", "claim2"]}
        mock_response_json_endpoint2 = {
            "another_claims": ["another_claim1", "another_claim2"]
        }
        with requests_mock.Mocker() as mock:
            mock_url = "https://provider2.example.com/userinfo"
            mock.register_uri(
                "POST", mock_url, json=mock_response_json_endpoint1, status_code=200
            )
            mock_url = "https://provider3.example.com/userinfo"
            mock.register_uri(
                "POST", mock_url, json=mock_response_json_endpoint2, status_code=200
            )
            resp = userinfo_flow()
            payload = json.loads(resp.message)
            assert resp.status == "200 OK"
            assert "sub" in payload
            assert remote_data_provider_config[0]["wrap_claim_name"] in payload
            assert remote_data_provider_config[1]["wrap_claim_name"] in payload
            assert (
                "claims" in payload[remote_data_provider_config[0]["wrap_claim_name"]]
            )
            assert (
                "another_claims"
                in payload[remote_data_provider_config[1]["wrap_claim_name"]]
            )

    @responses.activate
    def test_remote_data_provider_timeout(
        self,
        remote_data_provider_config,
        userinfo_flow,
    ):
        """
        Test that the remote data provider request handles
        remote timeouts correctly.
        """
        del remote_data_provider_config[1]
        remote_data_provider_config[0]["api_retries"] = 4
        remote_data_provider_endpoint = remote_data_provider_config[0]

        with requests_mock.Mocker() as mock:
            mock_url = "https://provider2.example.com/userinfo"
            mock.register_uri("POST", mock_url, exc=requests.exceptions.Timeout)

            resp = userinfo_flow()
            payload = json.loads(resp.message)
            assert resp.status == "200 OK"
            assert "sub" in payload
            assert remote_data_provider_endpoint["wrap_claim_name"] not in payload
            assert mock.call_count == remote_data_provider_endpoint["api_retries"]

    @responses.activate
    def test_remote_data_provider_invalid_scopes(
        self,
        remote_data_provider_config,
        userinfo_flow,
    ):
        """
        Test that the remote data provider request with invalid requested scope is ignored properly.
        """
        remote_data_provider_config[0]["require_scopes"] = ["email"]
        remote_data_provider_config[0]["ignore_api_error"] = False
        remote_data_provider_endpoint = remote_data_provider_config[0]

        mock_response_json = {"claims": ["claim1", "claim2"]}
        with requests_mock.Mocker() as mock:
            mock_url = "https://provider2.example.com/userinfo"
            mock.register_uri(
                "POST", mock_url, json=mock_response_json, status_code=200
            )
            resp = userinfo_flow()
            payload = json.loads(resp.message)
            assert resp.status == "200 OK"
            assert "sub" in payload
            assert remote_data_provider_endpoint["wrap_claim_name"] not in payload

    @responses.activate
    def test_remote_data_provider_custom_scopes(
        self,
        remote_data_provider_config,
        userinfo_flow,
    ):
        """
        Test that the remote data provider request is handled properly.
        """
        remote_data_provider_config[0]["require_scopes"] = ["eduperson"]
        remote_data_provider_endpoint = remote_data_provider_config[0]

        mock_response_json = {"claims": ["claim1", "claim2"]}
        with requests_mock.Mocker() as mock:
            mock_url = "https://provider2.example.com/userinfo"
            mock.register_uri(
                "POST", mock_url, json=mock_response_json, status_code=200
            )

            resp = userinfo_flow()
            payload = json.loads(resp.message)
            assert resp.status == "200 OK"
            assert "sub" in payload
            assert remote_data_provider_endpoint["wrap_claim_name"] in payload

    @responses.activate
    def test_remote_data_provider_no_wrap_claim(
        self,
        remote_data_provider_config,
        userinfo_flow,
    ):
        """
        Test that the remote data provider request is handled properly.
        """
        remote_data_provider_endpoint = remote_data_provider_config[0]
        del remote_data_provider_endpoint["wrap_claim_name"]
        mock_response_json = {"claims": ["claim1", "claim2"]}
        with requests_mock.Mocker() as mock:
            mock_url = "https://provider2.example.com/userinfo"
            mock.register_uri(
                "POST", mock_url, json=mock_response_json, status_code=200
            )

            resp = userinfo_flow()
            payload = json.loads(resp.message)
            assert resp.status == "200 OK"
            assert "sub" in payload
            assert "claims" in payload

    @responses.activate
    def test_remote_data_provider_wrong_configuration(
        self,
        remote_data_provider_config,
        frontend_config,
    ):
        """
        Test that the remote data provider request is handled properly if there is an error in configuration.
        """
        remote_data_provider_endpoint = remote_data_provider_config[0]
        del remote_data_provider_endpoint["api_username"]
        frontend_config["jwt_access_token"] = True
        with pytest.raises(SATOSAConfigurationError) as e:
            create_frontend(frontend_config)
        assert (
            "Error in configuration '1 validation error for RemoteDataProviderConfig\napi_username\n"
            in e.value.args[0]
        )


class TestAttributeAuth:
    @pytest.fixture
    def token(self):
        return "Bearer valid_token"

    @pytest.fixture
    def bad_token(self):
        return "Bearer bad_token"

    @pytest.fixture
    def expired_token(self):
        return "Bearer expired_token"

    @pytest.fixture
    def endpoint_context(self, token, expired_token):
        """
        TODO: It's possible that this can be done in a better
        way using monkeypatch? It's hacky and stupid anyway.
        """

        class TOKEN(AccessToken):
            value = token[len("Bearer ") :]

            def is_active():
                return True

        class GRANT:
            def __init__(self):
                at = AccessToken(value=token[len("Bearer ") :])
                self.issued_token = [at]
                self.authentication_event = {"valid_until": 9999999999}

        class SM:
            def get_session_info_by_token(self, tk, grant):
                return {
                    "grant": GRANT(),
                    "client_id": "client1",
                    "user_id": "user_id",
                }

        class EC:
            session_manager = SM()

            def __init__(self, *args):
                pass

            def userinfo(self, user_id, client_id):
                return {"attr1": "correct_value", "attr2": "correct_value"}

        return EC

    @pytest.fixture
    def AttributeAuth_with_matching_attributes(self, endpoint_context):
        AttributeAuth.CHECK_FOR_ATTRIBUTES = True
        AttributeAuth.ATTRIBUTES = {
            "attr1": ["correct_value", "another_value"],
            "attr2": ["correct_value"],
        }
        return AttributeAuth(endpoint_context)

    @pytest.fixture
    def AttributeAuth_with_matching_attributes_wrong_values(self, endpoint_context):
        AttributeAuth.CHECK_FOR_ATTRIBUTES = True
        AttributeAuth.ATTRIBUTES = {"attr1": ["wrong_value"], "attr2": ["wrong_value"]}
        return AttributeAuth(endpoint_context)

    @pytest.fixture
    def AttributeAuth_with_nonmatching_attributes(self, endpoint_context):
        AttributeAuth.CHECK_FOR_ATTRIBUTES = True
        AttributeAuth.ATTRIBUTES = {
            "attr3": ["attr3_value1"],
            "attr4": ["attr4_value1", "attr4_value2"],
        }
        return AttributeAuth(endpoint_context)

    @pytest.fixture
    def AttributeAuth_without_attributes(self, endpoint_context):
        AttributeAuth.CHECK_FOR_ATTRIBUTES = False
        AttributeAuth.ATTRIBUTES = {}
        return AttributeAuth(endpoint_context)

    def test_is_usable(self, AttributeAuth_without_attributes):
        """
        Test AttributeAuth is_usable with both an invalid and valid header.
        """
        auth_info = "Bearer token1"
        assert AttributeAuth_without_attributes.is_usable(authorization_token=auth_info)
        auth_info = "token1"
        assert not AttributeAuth_without_attributes.is_usable(
            authorization_token=auth_info
        )

    def test_verify_invalid_token(self, AttributeAuth_without_attributes, bad_token):
        """
        Test AttributeAuth verify with invalid token.
        """
        with pytest.raises(ClientAuthenticationError):
            AttributeAuth_without_attributes.verify(authorization_token=bad_token)

    def test_verify_expired_token(
        self, AttributeAuth_with_matching_attributes, expired_token
    ):
        """
        Test AttributeAuth verify with a valid but expired token.
        """
        with pytest.raises(ClientAuthenticationError):
            AttributeAuth_with_matching_attributes.verify(
                authorization_token=expired_token
            )

    def test_verify_valid_token(self, AttributeAuth_without_attributes, token):
        """
        Test AttributeAuth verify with valid token and no attribute checks.
        """
        ret = AttributeAuth_without_attributes.verify(authorization_token=token)
        assert ret == {"client_id": "client1", "method": "attributeauth"}

    def test_verify_missing_attributes(
        self, AttributeAuth_with_nonmatching_attributes, token
    ):
        """
        Test AttributeAuth verify with valid token but not all attributes required
        matching.
        """
        with pytest.raises(ClientAuthenticationError):
            AttributeAuth_with_nonmatching_attributes.verify(authorization_token=token)

    def test_verify_wrong_attribute_values(
        self, AttributeAuth_with_matching_attributes_wrong_values, token
    ):
        """
        Test AttributeAuth verify with valid token and the correct attributes but wrong
        values.
        """
        with pytest.raises(ClientAuthenticationError):
            AttributeAuth_with_matching_attributes_wrong_values.verify(
                authorization_token=token
            )

    def test_verify_matching_attributes(
        self, AttributeAuth_with_matching_attributes, token
    ):
        """
        Test AttributeAuth verify with valid token and all attributes required matching.
        """
        ret = AttributeAuth_with_matching_attributes.verify(authorization_token=token)
        assert ret == {"client_id": "client1", "method": "attributeauth"}


class TestClientDBHashedSecrets:

    @pytest.fixture
    def mock_create_engine(self):
        with patch("satosa_oidc_frontend.frontend.create_engine") as mock:
            mock.return_value = MagicMock(name="mock_engine")
            yield mock

    @pytest.fixture
    def mock_sessionmaker(self):
        with patch("satosa_oidc_frontend.frontend.sessionmaker") as mock:
            mock.return_value = MagicMock(name="mock_session")
            yield mock

    @pytest.fixture
    def mock_engine(self):
        with patch("satosa_oidc_frontend.frontend.engine") as mock:
            mock.url = "sqlite:///test.db"
            yield mock

    def test_no_db_uri(self, mock_engine, mock_sessionmaker):
        client_db = ClientDBHashedSecrets()

        mock_sessionmaker.assert_called_once_with(bind=mock_engine)
        assert client_db.session_maker == mock_sessionmaker.return_value

    def test_same_db_uri(self, mock_engine, mock_sessionmaker):
        client_db = ClientDBHashedSecrets(db_uri=mock_engine.url)

        mock_sessionmaker.assert_called_once_with(bind=mock_engine)
        assert client_db.session_maker == mock_sessionmaker.return_value

    def test_different_db_uri(self, mock_create_engine, mock_sessionmaker):
        db_uri = "sqlite:///other.db"
        client_db = ClientDBHashedSecrets(db_uri=db_uri)

        mock_create_engine.assert_called_once_with(db_uri, echo=False)
        mock_sessionmaker.assert_called_once_with(bind=mock_create_engine.return_value)
        assert client_db.session_maker == mock_sessionmaker.return_value
