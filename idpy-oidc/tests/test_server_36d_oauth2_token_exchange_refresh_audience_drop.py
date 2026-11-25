"""
Refresh-grant-issued tokens on a Token-Exchange session lose the `aud`
the exchanged token carried.

Root cause: the refresh helpers minted the new access and refresh tokens
without `token_args` — `scope` was propagated from the based-on token but
`resources` never was (`oauth2/token_helper/refresh_token.py`; same shape
in `oidc/token_helper/refresh_token.py`). The suite is parametrized over
both Token endpoint classes so each helper is exercised independently.
The refresh-minted token's own `resources` was empty, and the `aud`
lookup chain — `token.resources` falling back to `grant.resources`
(`oauth2/introspection.py`, and the equivalent in the JWT payload
builders) — came up empty, because `ExchangeGrant.resources` is
deliberately empty (per-token resources are the authoritative,
post-policy source; see the 36c suite).

Pre-fix manifestation, audience-bearing cross-client TE then Refresh:

    TE-issued AT        aud present (JWT + introspection)
    TE-issued RT        aud present (introspection)
    Refresh-issued AT   aud LOST    (JWT + introspection)
    Refresh-issued RT   aud LOST    (introspection)

The fix carries the based-on token's resources into the refresh-minted
AT and RT (mirroring how scope is carried), so audience confinement
survives a refresh. These tests assert that invariant — the
refresh-issued tokens carry the same `aud` as the TE-issued tokens they
descend from — for both helpers; they failed before the fix and pass
after it. Plain guards pin the TE-side `aud` (present before the
refresh) and the refresh itself succeeding.
"""

import os

import pytest
from cryptojwt.jws.jws import factory
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

REQUESTED_AUDIENCE = "https://rs.example.com/audience"

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


class TestIssueCRefreshLosesAudience(object):
    @pytest.fixture(
        autouse=True,
        params=[
            "idpyoidc.server.oauth2.token.Token",
            "idpyoidc.server.oidc.token.Token",
        ],
        ids=["oauth2-helper", "oidc-helper"],
    )
    def create_endpoint(self, request):
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
                    "class": request.param,
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
                                "expires_in": 600,
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
        # Cross-client exchange so the refresh runs on an ExchangeGrant — the
        # session whose grant-level resources are (deliberately) empty.
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
        session_id = self._create_session(AUTH_REQ)
        grant = self.context.authz(session_id, AUTH_REQ)
        code = self._mint_code(grant, AUTH_REQ["client_id"])

        _treq = TOKEN_REQ.to_dict()
        _treq["code"] = code.value
        _req = self.endpoint.parse_request(_treq)
        _resp = self.endpoint.process_request(request=_req)
        return _resp["response_args"]["access_token"]

    def _exchange(self, subject_token, requested_token_type=None):
        """Cross-client, audience-bearing exchange: client_2 exchanges
        client_1's AT. Returns the token endpoint response args."""
        kwargs = {}
        if requested_token_type is not None:
            kwargs["requested_token_type"] = requested_token_type
        te_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=subject_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            client_id="client_2",
            client_secret="hemligt2",
            audience=[REQUESTED_AUDIENCE],
            **kwargs,
        )
        # A dict request parses identically on both Token endpoint variants
        # (their declared request_format differs: json vs urlencoded).
        _req = self.endpoint.parse_request(te_req.to_dict())
        return self.endpoint.process_request(request=_req)["response_args"]

    def _te_refresh_token(self, input_at):
        """Exchange the input AT for a refresh token; return its value.
        (The TE response carries the issued token in `access_token`.)"""
        resp = self._exchange(
            input_at,
            requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
        )
        assert (
            resp["issued_token_type"]
            == "urn:ietf:params:oauth:token-type:refresh_token"
        )
        return resp["access_token"]

    def _refresh(self, refresh_token_value):
        """Run the Refresh grant on the TE session; return the response args."""
        _req = self.endpoint.parse_request(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_value,
                "client_id": "client_2",
                "client_secret": "hemligt2",
            }
        )
        return self.endpoint.process_request(request=_req, issue_refresh=True)[
            "response_args"
        ]

    def _introspect(self, token_value):
        _req = self.introspection_endpoint.parse_request(
            {
                "token": token_value,
                "client_id": "client_2",
                "client_secret": "hemligt2",
            }
        )
        return self.introspection_endpoint.process_request(_req)["response_args"]

    @staticmethod
    def _jwt_aud(token_value):
        """Return the JWT payload `aud` as a set (handles absent / str / list)."""
        aud = factory(token_value).jwt.payload().get("aud")
        if aud is None:
            return set()
        if isinstance(aud, str):
            return {aud}
        return set(aud)

    # ----- guards: aud present on the TE side; the refresh itself works -----

    def test_te_tokens_carry_aud_before_refresh(self):
        """The TE-issued AT (JWT + introspection) and RT (introspection) carry
        the requested audience — the state the refresh must preserve."""
        input_at = self._input_access_token()
        te_at = self._exchange(input_at)["access_token"]
        assert self._jwt_aud(te_at) == {REQUESTED_AUDIENCE}
        assert self._introspect(te_at).get("aud") == [REQUESTED_AUDIENCE]

        te_rt = self._te_refresh_token(self._input_access_token())
        assert self._introspect(te_rt).get("aud") == [REQUESTED_AUDIENCE]

    def test_refresh_succeeds_on_te_session(self):
        """Not a bug test: the Refresh grant on a TE session mints a usable
        AT and RT. Guards against the aud assertions failing for the wrong
        reason (e.g. a rejected refresh)."""
        te_rt = self._te_refresh_token(self._input_access_token())
        resp = self._refresh(te_rt)
        assert "access_token" in resp
        assert "refresh_token" in resp
        assert factory(resp["access_token"]).jwt.payload()

    # ----- audience confinement must survive the refresh --------------------

    def test_refresh_at_jwt_carries_aud(self):
        """The refresh-issued AT must carry the audience in its JWT `aud`."""
        te_rt = self._te_refresh_token(self._input_access_token())
        resp = self._refresh(te_rt)

        assert self._jwt_aud(resp["access_token"]) == {REQUESTED_AUDIENCE}

    def test_refresh_at_introspection_carries_aud(self):
        """Introspection of the refresh-issued AT must report the audience."""
        te_rt = self._te_refresh_token(self._input_access_token())
        resp = self._refresh(te_rt)

        assert self._introspect(resp["access_token"]).get("aud") == [REQUESTED_AUDIENCE]

    def test_refresh_rt_introspection_carries_aud(self):
        """Introspection of the refresh-issued RT must report the audience."""
        te_rt = self._te_refresh_token(self._input_access_token())
        resp = self._refresh(te_rt)

        assert self._introspect(resp["refresh_token"]).get("aud") == [
            REQUESTED_AUDIENCE
        ]
