"""
`MintingNotAllowed` is caught by the wrong class. The Token Exchange
handler is dead code and the refusal leaks the raw exception text with
the wrong error code.

Two unrelated classes shared the name `MintingNotAllowed`:
`idpyoidc.server.session.__init__` defines the one that
`grant.mint_token` raises (`grant.py`: "Minting of <class> not
supported", "Token inactive"); `idpyoidc.server.session.token` defined
a second one that was never raised anywhere. The Token Exchange helper
imported the `session.token` class, so its `except MintingNotAllowed`
block, which returns `invalid_grant` with a stable description, could
never match. The exception escaped to the Token endpoint's generic
outer handler, which returned `invalid_request` with the raw internal
exception string as `error_description`. The same wrong import killed
the graceful-degradation handlers in
`oidc/token_helper/access_token.py` and
`oidc/backchannel_authentication.py` (their oauth2 twin imports the
correct class).

The fix keeps a single canonical class in `idpyoidc.server.session`
(re-exported from `session.token` for backwards compatibility) and has
every site import it, reviving all the dead handlers at once.

The regression tests exercise the empirically-observed behaviour: a token
exchange requesting a refresh token from a subject AT whose usage rules
don't permit minting one. They assert that the refusal is reported as
`invalid_grant` with the handler's stable description, and that there
is exactly one `MintingNotAllowed` class so every handler catches what
is raised; they failed before the fix and pass after it. A plain guard
pins the refusal itself (the exchange must not succeed), so the other
tests cannot pass for the wrong reason.
"""

import os

import pytest
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.key_jar import build_keyjar

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


class TestIssueDMintingNotAllowed(object):
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
                            # The minted AT may NOT mint refresh tokens — an
                            # AT -> TE -> RT exchange must be refused by the
                            # supports_minting check in grant.mint_token.
                            "access_token": {
                                "supports_minting": ["access_token"],
                                "expires_in": 600,
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
                    "kwargs": {"lifetime": 3600, "add_claims_by_scope": True},
                },
                "refresh": {
                    "class": "idpyoidc.server.token.jwt_token.JWTToken",
                    "kwargs": {"lifetime": 3600},
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
        server.keyjar.import_jwks(CLIENT_KEYJAR.export_jwks(), "client_1")
        self.endpoint = server.get_endpoint("token")
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
        session_id = self._create_session(AUTH_REQ)
        grant = self.context.authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _treq = TOKEN_REQ.to_dict()
        _treq["code"] = code.value
        _req = self.endpoint.parse_request(_treq)
        _resp = self.endpoint.process_request(request=_req)
        return _resp["response_args"]["access_token"]

    def _exchange_for_refresh_token(self, subject_token):
        """Exchange an AT for a refresh token — refused, since the subject
        AT's usage rules don't list refresh_token. Returns the error
        response."""
        te_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=subject_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
            client_id="client_1",
            client_secret="hemligt",
        )
        _req = self.endpoint.parse_request(te_req.to_dict())
        return self.endpoint.process_request(request=_req)

    # ----- guard: the refusal itself ----------------------------------------

    def test_exchange_to_refresh_token_is_refused(self):
        """Not a bug test: the exchange must be refused (the subject AT may
        not mint refresh tokens). Guards against the xfails passing or
        failing for the wrong reason."""
        input_at = self._input_access_token()
        resp = self._exchange_for_refresh_token(input_at)

        assert "error" in resp
        assert "access_token" not in resp.get("response_args", {})

    # ----- the refusal must come from the TE handler, not the outer catch ---

    def test_refusal_is_invalid_grant_with_stable_description(self):
        """A grant that does not permit minting the requested token type is
        an invalid_grant case, reported with the TE handler's stable
        description — not the raw internal exception string."""
        input_at = self._input_access_token()
        resp = self._exchange_for_refresh_token(input_at)

        assert resp["error"] == "invalid_grant"
        assert resp["error_description"] == "Token Exchange not allowed with that token"

    def test_single_minting_not_allowed_class(self):
        """There must be exactly one MintingNotAllowed class, so that every
        handler catches what grant.mint_token raises. This is what revives
        the dead handlers in the oidc access-token helper and the
        backchannel-authentication endpoint as well."""
        from idpyoidc.server.session import MintingNotAllowed as raised_cls
        from idpyoidc.server.session.token import MintingNotAllowed as caught_cls

        assert raised_cls is caught_cls
