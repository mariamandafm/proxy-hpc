"""
Sessions reloaded from storage downcast `ExchangeGrant` to base `Grant`.

The storage layer is correct: `SessionDB.serialize_grant_session` stores
`grant_type=grant.type` and `deserialize_grant_session` dispatches on it,
reconstructing an `ExchangeGrant`. The defect was in the bridge that feeds
the reloaded session back into the idpy-oidc session manager:
`_load_session_from_token` loaded the grant under a hardcoded
`"idpyoidc.server.session.grant.Grant"` class string, for both the
`grant_key` and `compatible_sid` entries. Every token-driven request that
rehydrated a token-exchange session therefore left a base `Grant` in
the session manager:

  * `exchange_request` was silently dropped (not in base `Grant.parameter`),
  * `ExchangeGrant.payload_arguments` was no longer used for any token
    minted after the reload. Base `Grant.payload_arguments` stamps the
    JWT `client_id` from the (inherited, original client's)
    `authorization_request`, which was the observed "refresh-issued AT JWT
    client_id = original client, introspection client_id = TE caller"
    divergence.

The fix loads the grant under its actual class. The regression tests run
a cross-client token exchange (the only path that creates an
`ExchangeGrant`), reload the session through `_load_session_from_token`,
and assert that the grant in the session manager keeps its class and its
`exchange_request`; they failed before the fix and pass after it. A
plain guard pins the storage layer returning the correctly-typed grant
(so any failure is provably in the bridge, not in SQL
[de]serialisation), and a sanity test guards the harness.

The tests use the SQL-backed session storage (`db_uri`), matching
deployment; the defect itself is storage-agnostic (the in-memory
`SessionDict` variant goes through the same bridge).
"""

from base64 import urlsafe_b64encode
from urllib.parse import parse_qs, urlparse

import pytest
from idpyoidc.message.oauth2 import TokenExchangeRequest
from idpyoidc.message.oidc import AccessTokenRequest, AccessTokenResponse
from idpyoidc.server.session.grant import ExchangeGrant

from tests.frontend.test_frontend import (
    CLIENT_ID,
    CLIENT_SECRET,
    JWKS,
    create_frontend,
    insert_userinfo,
    response_types_supported,
    setup_for_authn_response,
)

CLIENT2_ID = "client2"
CLIENT2_SECRET = "client_secret2"

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


@pytest.fixture
def frontend_config():
    return {
        "response_types_supported": response_types_supported,
        "enable_introspection_endpoint": True,
        "allowed_scopes": ["openid", "email", "offline_access"],
        "subject_types_supported": ["pairwise"],
        "claim_types_supported": ["normal"],
        "response_modes_supported": ["query", "form_post"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            TOKEN_EXCHANGE_GRANT,
        ],
        "jwks": JWKS,
        "token_session_encryption_password": "password",
        "db_uri": "sqlite:///:memory:",
        "registration_authn": ["public"],
        "scopes_supported": ["openid", "email", "offline_access", "eduperson"],
        "client_db_enable_import": False,
    }


def basic_auth(client_id, client_secret):
    credentials = "{}:{}".format(client_id, client_secret)
    return "Basic {}".format(
        urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
    )


def insert_clients(frontend, redirect_uri):
    common = {
        "response_types_supported": response_types_supported,
        "redirect_uris": [(redirect_uri, "")],
        "allowed_scopes": ["openid", "email", "offline_access", "eduperson"],
    }
    frontend.client_db[CLIENT_ID] = {**common, "client_secret": CLIENT_SECRET}
    frontend.client_db[CLIENT2_ID] = {**common, "client_secret": CLIENT2_SECRET}


class TestExchangeGrantReload(object):
    def _exchanged_access_token(self, context, frontend_config, authn_req):
        """Auth-code flow for CLIENT_ID, then a cross-client token exchange
        by CLIENT2_ID (which creates the ExchangeGrant). Returns the
        frontend and the TE-issued access token."""
        frontend = create_frontend(frontend_config)
        frontend.register_endpoints(["test_backend"])

        insert_clients(frontend, authn_req["redirect_uri"])
        insert_userinfo(frontend, "test_user")
        authn_req["response_type"] = "code"
        authn_req["scope"] += " offline_access"
        authn_req["prompt"] = "consent"
        internal_response = setup_for_authn_response(context, frontend, authn_req)
        http_resp = frontend.handle_authn_response(context, internal_response)
        code = parse_qs(urlparse(http_resp.message).query)["code"][0]

        context.request = AccessTokenRequest(
            redirect_uri=authn_req["redirect_uri"], code=code
        ).to_dict()
        context.request_authorization = basic_auth(CLIENT_ID, CLIENT_SECRET)
        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        subject_token = parsed["access_token"]

        context.request = TokenExchangeRequest(
            grant_type=TOKEN_EXCHANGE_GRANT,
            subject_token=subject_token,
            subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        ).to_dict()
        context.request_authorization = basic_auth(CLIENT2_ID, CLIENT2_SECRET)
        response = frontend.handle_token(context)
        parsed = AccessTokenResponse().deserialize(response.message, "json")
        assert "access_token" in parsed, parsed.to_dict()
        return frontend, parsed["access_token"]

    def _reloaded_manager_grant(self, frontend, token):
        """Reload the session from storage the way every token-driven
        request does, then return the grant as the session manager sees it."""
        frontend._load_session_from_token(token)
        _session_info = (
            frontend.endpoint_context.session_manager.get_session_info_by_token(
                token, grant=True, handler_key="access_token"
            )
        )
        return _session_info["grant"]

    # ----- guards ------------------------------------------------------------

    def test_cross_client_exchange_succeeds(self, context, frontend_config, authn_req):
        """Not a bug test: the cross-client exchange mints a token. Guards
        against the reload assertions failing for the wrong reason."""
        frontend, te_at = self._exchanged_access_token(
            context, frontend_config, authn_req
        )
        assert te_at

    def test_storage_returns_exchange_grant(self, context, frontend_config, authn_req):
        """The storage layer reconstructs the right class: the grant returned
        by _load_session_from_token (i.e. SessionDB.deserialize_grant_session)
        is an ExchangeGrant. Pins the defect to the bridge, not the SQL
        [de]serialisation."""
        frontend, te_at = self._exchanged_access_token(
            context, frontend_config, authn_req
        )
        loaded = frontend._load_session_from_token(te_at)
        assert isinstance(loaded["grant"], ExchangeGrant)

    # ----- the session manager must see the same grant the storage returned --

    def test_reloaded_session_grant_is_exchange_grant(
        self, context, frontend_config, authn_req
    ):
        """After a reload, the grant in the session manager must still be an
        ExchangeGrant."""
        frontend, te_at = self._exchanged_access_token(
            context, frontend_config, authn_req
        )
        grant = self._reloaded_manager_grant(frontend, te_at)

        assert isinstance(grant, ExchangeGrant)

    def test_reloaded_session_keeps_exchange_request(
        self, context, frontend_config, authn_req
    ):
        """After a reload, the grant must keep the exchange_request (the TE
        caller's identity), which ExchangeGrant.payload_arguments stamps into
        minted JWTs as client_id."""
        frontend, te_at = self._exchanged_access_token(
            context, frontend_config, authn_req
        )
        grant = self._reloaded_manager_grant(frontend, te_at)

        exchange_request = getattr(grant, "exchange_request", None)
        assert exchange_request
        assert exchange_request["client_id"] == CLIENT2_ID
