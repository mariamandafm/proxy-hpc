import pytest
from idpyoidc.message.oauth2 import AuthorizationRequest
from idpyoidc.message.oidc import Claims, ClaimsRequest
from tests.frontend.test_frontend import (
    CLIENT_ID,
    EXTRA_SCOPES,
    JWKS,
    response_types_supported,
)


@pytest.fixture
def authn_req():
    state = "my_state"
    nonce = "nonce"
    redirect_uri = "https://client.example.com"
    claims_req = ClaimsRequest(id_token=Claims(email=None))
    req = AuthorizationRequest(
        client_id=CLIENT_ID,
        state=state,
        scope="openid",
        response_type="id_token",
        redirect_uri=redirect_uri,
        nonce=nonce,
        claims=claims_req,
    ).to_dict()
    return req


@pytest.fixture
def authn_req_extra_scopes():
    state = "my_state"
    nonce = "nonce"
    redirect_uri = "https://client.example.com"
    claims_req = ClaimsRequest(id_token=Claims(email=None))
    req = AuthorizationRequest(
        client_id=CLIENT_ID,
        state=state,
        scope="openid email eduperson",
        response_type="id_token",
        redirect_uri=redirect_uri,
        nonce=nonce,
        claims=claims_req,
    ).to_dict()
    return req


@pytest.fixture
def attribute_auth_config():
    return {
        "client_authn_method_mapping": {
            "attribute_auth": "satosa_oidc_frontend.AttributeAuth",
        },
        "attribute_auth": {
            "eduperson_principal_name": ["test@example.com"],
            "eduperson_scoped_affiliation": ["student@example.com"],
        },
        "registration_authn": ["attribute_auth"],
    }


@pytest.fixture
def frontend_config():
    config = {
        "response_types_supported": response_types_supported,
        "enable_registration_endpoint": True,
        "enable_introspection_endpoint": True,
        "enable_revocation_endpoint": True,
        "subject_types_supported": ["pairwise"],
        "claim_types_supported": ["normal"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_modes_supported": ["query", "form_post"],
        "jwks": JWKS,
        "token_session_encryption_password": "password",
        "registration_authn": ["public"],
        "scopes_supported": ["openid", "email", "offline_access", "eduperson"],
        "client_db_enable_import": False,
    }

    return config


@pytest.fixture
def frontend_config_extra_scopes():
    config = {
        "response_types_supported": response_types_supported,
        "enable_registration_endpoint": True,
        "enable_introspection_endpoint": True,
        "enable_revocation_endpoint": True,
        "subject_types_supported": ["pairwise"],
        "claim_types_supported": ["normal"],
        "response_modes_supported": ["query", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "jwks": JWKS,
        "token_session_encryption_password": "password",
        "scopes_to_claims": EXTRA_SCOPES,
        "scopes_supported": ["openid", "email", "offline_access", "eduperson"],
    }

    return config
