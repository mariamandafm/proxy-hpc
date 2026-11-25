"""
Token-Exchange-issued access token JWT carries no `aud` claim
despite an `audience` (or `resource`) request parameter.

Root cause:

  * Defect 1: the `audience` parameter is dropped: the TE helper builds
    `_token_args["resources"]` only from `request["resource"]`, so an
    audience-only exchange leaves the new token's resources empty.
  * Defect 2: the JWT payload `aud` is overwritten:
    `ExchangeGrant.payload_arguments` rebuilds the payload as
    `aud = self.resources` (grant.py:577), discarding the per-token
    `item.resources`. `ExchangeGrant.resources` is never populated, so the
    JWT `aud` is always empty on the cross-client path — even when a
    `resource` (which *does* reach `_token_args`) was requested.

Pre-fix manifestation matrix — JWT `aud` of a TE-issued access token:

                  audience-only request    resource request
    same-client   DROPPED (Defect 1)       works
    cross-client  DROPPED (Defects 1 + 2)  DROPPED (Defect 2)

Defect 1 (audience dropped in the TE helper, before minting) affected BOTH
paths — an audience-only request never reached `_token_args`. Defect 2 (the
`grant.py` `aud = self.resources` overwrite) was specific to ExchangeGrant,
i.e. the cross-client path, and additionally discarded a `resource` that
otherwise worked same-client.

The fix folds both `audience` and `resource` into the new token's resources
before minting and stops the ExchangeGrant payload from overwriting `aud`,
so every cell of the matrix now carries the requested audience/resource in
the JWT `aud`, and these tests assert that invariant across the matrix,
together with the invariants at its edges: a request with neither
`audience` nor `resource` yields no `aud` (`ExchangeGrant.resources` is
deliberately not seeded — it would carry pre-filter values); a request
with both parameters carries their union; and the rest of the JWT payload
(`scope`, `jti`, `client_id`) is unaffected by the removal of the payload
rebuild. The matrix tests failed before the fix and pass after it. A
sanity test guards the harness.

Out of scope (Issue C): the *introspection* half of Issue 3 — in the
deployed proxy, introspection of TE tokens DOES show `aud` via a
deployment-specific custom audience policy that is not in the in-tree code.
These tests therefore assert only on the decoded JWT payload.
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
REQUESTED_RESOURCE = "https://rs.example.com/resource"

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


class TestIssueBTokenExchangeAudienceDrop(object):
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
        # Cross-client exchange is required to exercise ExchangeGrant (and thus
        # Defect 2); a same-client exchange mints on the original grant.
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

    def _exchange_for_at(self, subject_token, audience=None, resource=None):
        """Cross-client exchange: client_2 exchanges client_1's AT."""
        kwargs = {}
        if audience is not None:
            kwargs["audience"] = audience
        if resource is not None:
            kwargs["resource"] = resource
        te_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=subject_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            client_id="client_2",
            client_secret="hemligt2",
            **kwargs,
        )
        _req = self.endpoint.parse_request(te_req.to_urlencoded())
        return self.endpoint.process_request(request=_req)["response_args"]

    def _exchange_same_client(self, subject_token, audience=None, resource=None):
        """Same-client exchange: client_1 exchanges its own AT. Mints on the
        original grant (no ExchangeGrant), so Defect 2 does not apply."""
        kwargs = {}
        if audience is not None:
            kwargs["audience"] = audience
        if resource is not None:
            kwargs["resource"] = resource
        te_req = TokenExchangeRequest(
            grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token=subject_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
            client_id="client_1",
            client_secret="hemligt",
            **kwargs,
        )
        _req = self.endpoint.parse_request(te_req.to_urlencoded())
        return self.endpoint.process_request(request=_req)["response_args"]

    @staticmethod
    def _jwt_aud(token_value):
        """Return the JWT payload `aud` as a set (handles absent / str / list)."""
        aud = factory(token_value).jwt.payload().get("aud")
        if aud is None:
            return set()
        if isinstance(aud, str):
            return {aud}
        return set(aud)

    # ----- sanity guard (must pass today AND after the fix) -----------------

    def test_token_exchange_with_audience_succeeds(self):
        """Not a bug test: the audience-bearing cross-client exchange mints a
        usable access token. Guards against the `aud` assertions failing for
        the wrong reason (e.g. a rejected request)."""
        input_at = self._input_access_token()
        resp = self._exchange_for_at(input_at, audience=[REQUESTED_AUDIENCE])
        assert "access_token" in resp
        # The returned value is a decodable JWT.
        assert factory(resp["access_token"]).jwt.payload()

    # ----- the JWT `aud` must reflect the requested audience/resource -------

    def test_audience_in_jwt_same_client(self):
        """An audience-only exchange must carry the audience in the JWT `aud`,
        including on the same-client path (Defect 1 was path-independent)."""
        input_at = self._input_access_token()
        resp = self._exchange_same_client(input_at, audience=[REQUESTED_AUDIENCE])

        assert self._jwt_aud(resp["access_token"]) == {REQUESTED_AUDIENCE}

    def test_audience_in_jwt_cross_client(self):
        """A cross-client TE-AT minted for a requested `audience` must carry
        that audience in its JWT `aud` claim."""
        input_at = self._input_access_token()
        resp = self._exchange_for_at(input_at, audience=[REQUESTED_AUDIENCE])

        assert self._jwt_aud(resp["access_token"]) == {REQUESTED_AUDIENCE}

    def test_resource_in_jwt_cross_client(self):
        """A cross-client TE-AT minted for a requested `resource` must carry it
        in the JWT `aud` claim (the ExchangeGrant payload overwrite no longer
        discards the per-token resources)."""
        input_at = self._input_access_token()
        resp = self._exchange_for_at(input_at, resource=[REQUESTED_RESOURCE])

        assert self._jwt_aud(resp["access_token"]) == {REQUESTED_RESOURCE}

    def test_resource_in_jwt_same_client(self):
        """The same-client `resource` path already carries `aud` correctly
        (no Defect 2 overwrite). It must keep working after the fix."""
        input_at = self._input_access_token()
        resp = self._exchange_same_client(input_at, resource=[REQUESTED_RESOURCE])

        assert self._jwt_aud(resp["access_token"]) == {REQUESTED_RESOURCE}

    # ----- invariants at the matrix's edges ----------------------------------

    def test_no_aud_without_audience_or_resource(self):
        """An exchange requesting neither `audience` nor `resource` must yield
        a JWT with no `aud` — on both paths. Pins down the decision NOT to
        seed `ExchangeGrant.resources` in `create_exchange_grant` (the grant
        is created before the resource/audience policies narrow the request,
        so grant-level seeding would carry pre-filter values into every
        token's `aud`)."""
        input_at = self._input_access_token()

        resp = self._exchange_for_at(input_at)
        assert self._jwt_aud(resp["access_token"]) == set()

        resp = self._exchange_same_client(input_at)
        assert self._jwt_aud(resp["access_token"]) == set()

    def test_audience_and_resource_combined_in_jwt(self):
        """A request carrying BOTH `audience` and `resource` must mint a JWT
        whose `aud` is exactly their union — the merge of the two lists is the
        core of the Defect 1 fix."""
        input_at = self._input_access_token()
        resp = self._exchange_for_at(
            input_at,
            audience=[REQUESTED_AUDIENCE],
            resource=[REQUESTED_RESOURCE],
        )

        assert self._jwt_aud(resp["access_token"]) == {
            REQUESTED_AUDIENCE,
            REQUESTED_RESOURCE,
        }

    def test_jwt_payload_survives_aud_fix(self):
        """The Defect 2 fix removed the payload rebuild in
        `ExchangeGrant.payload_arguments` that also used to set `scope` and
        `jti`. The cross-client TE-AT must still carry `scope`, `jti` and the
        TE caller's `client_id` alongside the fixed `aud`."""
        input_at = self._input_access_token()
        resp = self._exchange_for_at(input_at, audience=[REQUESTED_AUDIENCE])
        payload = factory(resp["access_token"]).jwt.payload()

        assert "offline_access" in payload["scope"]  # str or list — `in` covers both
        assert payload["jti"]
        assert payload["client_id"] == "client_2"
        assert payload["aud"] == [REQUESTED_AUDIENCE]
