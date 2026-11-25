"""
Issue: Token-Exchange-issued access token reports three different
lifetimes across the JWT payload, introspection, and the TE response.

Root cause:

  * ExchangeGrant.usage_rules hardcodes access_token expires_in = 60, so the
    JWT is signed with exp = iat + 60 and the session record is first set to
    now + 60.
  * token_exchange.py then runs `new_token.expires_at = token.expires_at`
    AFTER the JWT is signed, clobbering ONLY the session record with the
    input subject_token's residual lifetime. The JWT is not re-minted.
  * The TE response's `expires_in` and introspection both read the
    overridden session record, so they report the input AT's residual while
    the JWT still says 60 s.

The fix bounds the TE-issued access token by the input subject
token's residual lifetime *before* minting, so the JWT exp, the session
record and the response expires_in all agree. The two regression tests
assert that invariant.

Note: the desync only manifests for *cross-client* exchange, where an
ExchangeGrant is created (token_exchange.py: caller client_id !=
subject-token owner). A same-client exchange mints on the original grant
and never desynced. The tests therefore exchange client_1's token as
client_2.
"""

import os

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar

from idpyoidc.message.oauth2 import TokenErrorResponse
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.message.oidc import AccessTokenRequest, AuthorizationRequest
from idpyoidc.server import Server
from idpyoidc.server.authn_event import create_authn_event
from idpyoidc.server.authz import AuthzHandling
from idpyoidc.server.client_authn import verify_client
from idpyoidc.server.configure import ASConfiguration
from idpyoidc.server.cookie_handler import CookieHandler
from idpyoidc.server.user_authn.authn_context import INTERNETPROTOCOLPASSWORD
from idpyoidc.server.user_info import UserInfo
from tests import CRYPT_CONFIG, SESSION_PARAMS

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
CLIENT_KEYJAR = build_keyjar(KEYDEFS)
COOKIE_KEYDEFS = [
    {"type": "oct", "kid": "sig", "use": ["sig"]},
    {"type": "oct", "kid": "enc", "use": ["enc"]},
]

# INPUT_AT_LIFETIME (600 s) is the regular access-token usage rule. Because it
# is shorter than the ExchangeGrant default and the token-handler lifetime, the
# fix must bound the TE-AT to ~600 s and report it consistently. Pre-fix, the
# JWT advertised the hardcoded 60 s while introspection/response advertised 600.
INPUT_AT_LIFETIME = 600
TOKEN_HANDLER_LIFETIME = 3600

AUTH_REQ = AuthorizationRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    scope=["openid", "offline_access"],
    state="STATE",
    response_type="code",
)

TOKEN_REQ = AccessTokenRequest(
    client_id="client_1",
    redirect_uri="https://example.com/cb",
    state="STATE",
    grant_type="authorization_code",
    client_secret="hemligt",
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


class TestIssueATokenExchangeATLifetime(object):
    @pytest.fixture(autouse=True)
    def create_endpoint(self):
        conf = {
            "issuer": "https://example.com/",
            "httpc_params": {"verify": False, "timeout": 1},
            "preference": {
                "subject_types_supported": ["public", "pairwise", "ephemeral"]
            },
            "cookie_handler": {
                "class": CookieHandler,
                "kwargs": {"keys": {"key_defs": COOKIE_KEYDEFS}},
            },
            "keys": {"uri_path": "jwks.json", "key_defs": KEYDEFS},
            "endpoint": {
                "authorization": {
                    "path": "authorization",
                    "class": "idpyoidc.server.oauth2.authorization.Authorization",
                    "kwargs": {},
                },
                "token": {
                    "path": "token",
                    "class": "idpyoidc.server.oidc.token.Token",
                    "kwargs": {
                        "client_authn_method": [
                            "client_secret_basic",
                            "client_secret_post",
                        ],
                    },
                },
                "introspection": {
                    "path": "introspection",
                    "class": "idpyoidc.server.oauth2.introspection.Introspection",
                    "kwargs": {
                        "client_authn_method": ["client_secret_post"],
                        "enable_claims_per_client": False,
                    },
                },
            },
            "authentication": {
                "anon": {
                    "acr": INTERNETPROTOCOLPASSWORD,
                    "class": "idpyoidc.server.user_authn.user.NoAuthn",
                    "kwargs": {"user": "diana"},
                }
            },
            "userinfo": {"class": UserInfo, "kwargs": {"db": {}}},
            "client_authn": verify_client,
            "template_dir": "template",
            "authz": {
                "class": AuthzHandling,
                "kwargs": {
                    "grant_config": {
                        "usage_rules": {
                            "authorization_code": {
                                "supports_minting": ["access_token", "refresh_token"],
                                "max_usage": 1,
                            },
                            "access_token": {
                                "supports_minting": ["access_token", "refresh_token"],
                                "expires_in": INPUT_AT_LIFETIME,
                            },
                            "refresh_token": {
                                "supports_minting": ["access_token", "refresh_token"],
                                "expires_in": 43200,
                            },
                        },
                        "expires_in": 43200,
                    }
                },
            },
            "token_handler_args": {
                "jwks_file": "private/token_jwks.json",
                "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                "token": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {
                        "lifetime": TOKEN_HANDLER_LIFETIME,
                        "add_claims_by_scope": True,
                    },
                },
                "refresh": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {"lifetime": TOKEN_HANDLER_LIFETIME},
                },
            },
            "session_params": SESSION_PARAMS,
        }
        server = Server(ASConfiguration(conf=conf, base_path=BASEDIR), cwd=BASEDIR)
        self.context = server.context
        self.context.map_supported_to_preferred()
        self.context.cdb["client_1"] = {
            "client_secret": "hemligt",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "response_types": ["code"],
            "allowed_scopes": ["openid", "profile", "offline_access"],
        }
        # A SECOND client is required: ExchangeGrant (and its hardcoded 60 s
        # access-token rule) is only created when the TE caller differs from
        # the subject token's owner client. A same-client exchange mints on the
        # original grant and never desyncs.
        self.context.cdb["client_2"] = {
            "client_secret": "hemligt2",
            "redirect_uris": [("https://example.com/cb", None)],
            "client_salt": "salted",
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types_supported": [
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ],
            "response_types": ["code"],
            "allowed_scopes": ["openid", "profile", "offline_access"],
        }
        server.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.endpoint = server.get_endpoint("token")
        self.introspection_endpoint = server.get_endpoint("introspection")
        self.session_manager = self.context.session_manager
        self.user_id = "diana"

    # ----- helpers ----------------------------------------------------------

    def _create_session(self, auth_req):
        ae = create_authn_event(self.user_id)
        return self.session_manager.create_session(
            ae, auth_req, self.user_id, client_id=auth_req["client_id"]
        )

    def _mint_code(self, grant, client_id):
        session_id = self.session_manager.encrypted_session_id(
            self.user_id, client_id, grant.id
        )
        usage_rules = grant.usage_rules.get("authorization_code", {})
        _code = grant.mint_token(
            session_id=session_id,
            context=self.context,
            token_class="authorization_code",
            token_handler=self.session_manager.token_handler["authorization_code"],
            usage_rules=usage_rules,
        )
        _exp_in = usage_rules.get("expires_in")
        if _exp_in:
            _code.expires_at = utc_time_sans_frac() + int(_exp_in)
        return _code

    def _input_access_token(self):
        """Run the auth-code flow and return the input AT (subject_token) value."""
        session_id = self._create_session(AUTH_REQ)
        grant = self.context.authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _treq = TOKEN_REQ.to_dict()
        _treq["code"] = code.value
        _req = self.endpoint.parse_request(_treq)
        _resp = self.endpoint.process_request(request=_req)
        return _resp["response_args"]["access_token"]

    def _exchange_for_at(self, subject_token):
        """Cross-client exchange: client_2 exchanges client_1's AT (this is
        what creates the ExchangeGrant and triggers Issue A)."""
        te_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=subject_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            client_id="client_2",
            client_secret="hemligt2",
        )
        _req = self.endpoint.parse_request(te_req.to_urlencoded())
        return self.endpoint.process_request(request=_req)["response_args"]

    def _introspect(self, token_value, client_id="client_1", client_secret="hemligt"):
        _req = self.introspection_endpoint.parse_request(
            {
                "token": token_value,
                "client_id": client_id,
                "client_secret": client_secret,
            }
        )
        return self.introspection_endpoint.process_request(_req)["response_args"]

    @staticmethod
    def _jwt_claims(token_value):
        return factory(token_value).jwt.payload()

    # ----- sanity guard (must pass today AND after the fix) ------------------

    def test_token_exchange_flow_sanity(self):
        """
        Not a bug test. Proves the harness is sound, so the xfails below
        fail for the real reason (the desync) and not a broken setup. Asserts
        only facts that hold both before and after the fix.
        """
        input_at = self._input_access_token()
        input_introspect = self._introspect(input_at)

        # The input AT is a normal auth-code-grant token; its lifetime is the
        # configured 600 s and its JWT and introspection agree (no cascade).
        assert input_introspect["active"] is True
        input_jwt = self._jwt_claims(input_at)
        assert abs((input_jwt["exp"] - input_jwt["iat"]) - INPUT_AT_LIFETIME) <= 2
        assert (
            abs((input_introspect["exp"] - input_introspect["iat"]) - INPUT_AT_LIFETIME)
            <= 2
        )

        # The exchange itself succeeds and yields a usable, active access token.
        resp = self._exchange_for_at(input_at)
        assert "access_token" in resp
        assert "expires_in" in resp
        assert (
            self._introspect(resp["access_token"], "client_2", "hemligt2")["active"]
            is True
        )

    # ----- bug demonstrations (assert the correct behaviour) ----------------

    def test_te_at_jwt_exp_matches_introspection_exp(self):
        """The same token must report the same expiry in its JWT and in
        introspection, and must not outlive the input subject token."""
        input_at = self._input_access_token()
        input_at_exp = self._introspect(input_at)["exp"]
        resp = self._exchange_for_at(input_at)
        te_at = resp["access_token"]

        jwt_exp = self._jwt_claims(te_at)["exp"]
        introspect_exp = self._introspect(te_at, "client_2", "hemligt2")["exp"]

        assert abs(jwt_exp - introspect_exp) <= 2
        # The TE-AT may never outlive the input subject token (Issue A bound).
        assert jwt_exp <= input_at_exp + 2

    def test_te_at_response_expires_in_matches_jwt(self):
        """The advertised expires_in must match the JWT's actual lifetime."""
        input_at = self._input_access_token()
        resp = self._exchange_for_at(input_at)
        te_at = resp["access_token"]

        te_jwt = self._jwt_claims(te_at)
        jwt_lifetime = te_jwt["exp"] - te_jwt["iat"]

        assert abs(resp["expires_in"] - jwt_lifetime) <= 2

    def test_expired_subject_token_session_record_is_rejected(self):
        """When the session record's expires_at is in the past the exchange must
        return invalid_request, not mint a zero-lifetime token.

        The JWT exp is left untouched so get_session_info_by_token accepts the
        token; only the session record's expires_at is wound back."""
        input_at = self._input_access_token()

        _session_info = self.session_manager.get_session_info_by_token(
            input_at, grant=True, handler_key="access_token"
        )
        token = next(
            t for t in _session_info["grant"].issued_token if t.value == input_at
        )
        token.expires_at = utc_time_sans_frac() - 10
        self.session_manager.set(
            self.session_manager.unpack_session_key(_session_info["branch_id"]),
            _session_info["grant"],
        )

        te_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=input_at,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            client_id="client_2",
            client_secret="hemligt2",
        )
        _req = self.endpoint.parse_request(te_req.to_urlencoded())
        resp = self.endpoint.process_request(request=_req)

        assert isinstance(resp, TokenErrorResponse)
        assert resp["error"] == "invalid_request"
        assert resp["error_description"] == "Subject token inactive"
