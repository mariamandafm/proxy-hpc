from http import HTTPStatus
from unittest.mock import Mock, patch

import pytest
from satosa_oidc_frontend.libraries.letty_api import (
    LettyClientsAPI,
    LettySecretVerifier,
    UnsupportedLettyOperation,
)
from satosa_oidc_frontend.types import ClientId, ClientInfo


@pytest.fixture
def _api_url() -> str:
    return "http://test.letty.org/api"


@pytest.fixture
def _letty_clients_api(_api_url: str) -> LettyClientsAPI:
    return LettyClientsAPI(_api_url)


@pytest.fixture
def _client_id() -> ClientId:
    return ClientId("APP-0FEBEB7A-AC27-4C6D-A378-1E148E778C63")


@pytest.fixture
def _client_raw_min(_client_id: ClientId) -> dict:
    return {
        "id": 1,
        "contacts": [{"type": "tech", "email": "tech@newsp.com"}],
        "service_type": "oidc",
        "metadata": {
            "oidc_grants": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "refresh_token",
            ],
            "oidc_redirect_uris": [
                "https://newsp.myorg.com/redirect",
                "https://newsp.myorg.com/redirect?q=1&r=2&q=3",
            ],
            "id": _client_id,
        },
    }


@pytest.fixture
def _expected_client_info_min(_api_url: str, _client_id: ClientId) -> ClientInfo:
    return ClientInfo(
        {
            "client_id": _client_id,
            "client_secret": LettySecretVerifier(_api_url, _client_id),
            "client_name": "",
            "client_uri": "",
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "refresh_token",
            ],
            "add_claims": {
                "always": {
                    "introspection": [
                        "entitlements",
                        "eduperson_entitlement",
                        "given_name",
                        "family_name",
                        "email",
                    ]
                },
                "by_scope": {
                    "introspection": True,
                },
            },
            "redirect_uris": [
                ["https://newsp.myorg.com/redirect", {}],
                ["https://newsp.myorg.com/redirect", {"q": ["1", "3"], "r": ["2"]}],
            ],
        }
    )


@pytest.fixture
def _client_raw_complete(_client_id: ClientId, _client_raw_min: dict) -> dict:
    return _client_raw_min | {
        "organization_name": "My Org",
        "organization_website": "https://myorg.com",
        "service_name": "New SP from My Org",
        "service_description": "The new SP from My Org",
        "service_website": "https://newsp.myorg.com",
        "service_logo_url": "https://newsp.myorg.com/logo",
        "privacy_policy_url": "https://newsp.myorg.com/policies",
        "terms_of_use_url": "https://newsp.myorg.com/terms",
        "trustmarks": ["https://refeds.org/sirtfi2"],
        "registration_authority": "urn:regauth.com:ABC123",
        "metadata": {
            "id": _client_id,
            "oidc_grants": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "refresh_token",
            ],
            "oidc_authn_methods": ["client_secret_basic", "client_secret_post"],
            "oidc_confidential": True,
            "oidc_pkce": ["S256"],
            "oidc_scopes": ["openid", "email", "profile"],
            "oidc_response_types": [["code"], ["code", "token"]],
            "oidc_redirect_uris": [
                "https://newsp.myorg.com/redirect",
                "https://newsp.myorg.com/redirect?q=1&r=2&q=3",
            ],
            "oidc_application_type": "web",
            "oidc_allowed_resource_servers": [
                "APP-CLIENT-123",
                "APP-CLIENT-456",
            ],
            "oidc_id_token_usage_rules": {
                "expires_in": 10,
            },
            "oidc_access_token_usage_rules": {
                "max_usage": 1,
                "expires_in": 20,
            },
            "oidc_refresh_token_usage_rules": {
                "max_usage": 2,
                "expires_in": 30,
                "supports_minting": ["access_token", "refresh_token"],
            },
            "oidc_authz_code_usage_rules": {
                "expires_in": 40,
                "supports_minting": ["access_token", "refresh_token"],
            },
            "oidc_revoke_refresh_on_issue": True,
        },
    }


@pytest.fixture
def _expected_client_info_complete(
    _expected_client_info_min: ClientInfo,
) -> ClientInfo:
    return ClientInfo(
        dict(_expected_client_info_min)
        | {
            "client_name": "New SP from My Org",
            "client_uri": "https://newsp.myorg.com",
            "organization_name": "My Org",
            "organization_website": "https://myorg.com",
            "service_description": "The new SP from My Org",
            "policy_uri": "https://newsp.myorg.com/policies",
            "tos_uri": "https://newsp.myorg.com/terms",
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "refresh_token",
            ],
            "allowed_scopes": ["openid", "email", "profile"],
            "add_claims": {
                "always": {
                    "introspection": [
                        "entitlements",
                        "eduperson_entitlement",
                        "given_name",
                        "family_name",
                        "email",
                    ]
                },
                "by_scope": {
                    "introspection": True,
                },
            },
            "response_types_supported": ["code", "code token"],
            "token_endpoint_client_authn_method": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "introspection_endpoint_client_authn_method": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "pkce_essential": True,
            "redirect_uris": [
                ["https://newsp.myorg.com/redirect", {}],
                ["https://newsp.myorg.com/redirect", {"q": ["1", "3"], "r": ["2"]}],
            ],
            "application_type": "web",
            "token_usage_rules": {
                "id_token": {
                    "expires_in": 10,
                },
                "access_token": {
                    "max_usage": 1,
                    "expires_in": 20,
                },
                "refresh_token": {
                    "max_usage": 2,
                    "expires_in": 30,
                    "supports_minting": ["access_token", "refresh_token"],
                },
                "code": {
                    "expires_in": 40,
                    "supports_minting": ["access_token", "refresh_token"],
                },
            },
            "revoke_refresh_on_issue": True,
        }
    )


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    LettyClientsAPI._get_and_cache_info_by_client_id.cache_clear()
    LettySecretVerifier._verify_secret_cached.cache_clear()


@patch("satosa_oidc_frontend.libraries.letty_api.api_session.get")
@patch(
    "satosa_oidc_frontend.libraries.letty_api.api_session.post",
    return_value=Mock(status_code=HTTPStatus.NO_CONTENT),
)
def test_client_with_min_info_exists(
    mock_post_verify_secret: Mock,
    mock_get_client_id: Mock,
    _letty_clients_api: LettyClientsAPI,
    _client_id: ClientId,
    _client_raw_min: dict,
    _expected_client_info_min: ClientInfo,
) -> None:
    mock_get_client_id_response = Mock()
    mock_get_client_id_response.status_code = HTTPStatus.OK
    mock_get_client_id_response.json.return_value = _client_raw_min
    mock_get_client_id.return_value = mock_get_client_id_response

    assert _client_id in _letty_clients_api
    assert _letty_clients_api[_client_id] == _expected_client_info_min
    assert _letty_clients_api.get(_client_id) == _expected_client_info_min
    assert _client_id in _letty_clients_api.keys()

    # GET client info by client ID should've been called
    # only once since it would cache the response
    mock_get_client_id.assert_called_once()

    # POST verify secret is called because of asserting the retrieved client info
    # (that includes Secret Verifier) with the expected info
    mock_post_verify_secret.assert_called_once()


@patch("satosa_oidc_frontend.libraries.letty_api.api_session.get")
@patch(
    "satosa_oidc_frontend.libraries.letty_api.api_session.post",
    return_value=Mock(status_code=HTTPStatus.NO_CONTENT),
)
def test_client_with_complete_info_exists(
    mock_post_verify_secret: Mock,
    mock_get_client_id: Mock,
    _letty_clients_api: LettyClientsAPI,
    _client_id: ClientId,
    _client_raw_complete: dict,
    _expected_client_info_complete: ClientInfo,
) -> None:
    mock_get_client_id_response = Mock()
    mock_get_client_id_response.status_code = HTTPStatus.OK
    mock_get_client_id_response.json.return_value = _client_raw_complete
    mock_get_client_id.return_value = mock_get_client_id_response

    assert _client_id in _letty_clients_api
    assert _letty_clients_api[_client_id] == _expected_client_info_complete
    assert _letty_clients_api.get(_client_id) == _expected_client_info_complete
    assert _client_id in _letty_clients_api.keys()

    # GET client info by client ID should've been called
    # only once since it would cache the response
    mock_get_client_id.assert_called_once()

    # POST verify secret is called because of asserting the retrieved client info
    # (that includes Secret Verifier) with the expected info
    mock_post_verify_secret.assert_called_once()


@patch(
    "satosa_oidc_frontend.libraries.letty_api.api_session.get",
    return_value=Mock(status_code=HTTPStatus.INTERNAL_SERVER_ERROR),
)
def test_letty_unexpected_error(
    mock_get_client_id: Mock,
    _letty_clients_api: LettyClientsAPI,
    _client_id: ClientId,
) -> None:
    assert _client_id not in _letty_clients_api
    assert _letty_clients_api.get(_client_id) == {}
    assert _client_id not in _letty_clients_api.keys()

    with pytest.raises(KeyError):
        _client_info = _letty_clients_api[_client_id]

    mock_get_client_id.assert_called_once()


def test_set_client_not_implemented(
    _letty_clients_api: LettyClientsAPI, _client_id: ClientId
) -> None:
    with pytest.raises(UnsupportedLettyOperation):
        _letty_clients_api[_client_id] = ClientInfo({})


def test_update_clients_not_implemented(_letty_clients_api: LettyClientsAPI) -> None:
    with pytest.raises(UnsupportedLettyOperation):
        _letty_clients_api.update({})


@patch(
    "satosa_oidc_frontend.libraries.letty_api.api_session.post",
    return_value=Mock(status_code=HTTPStatus.NO_CONTENT),
)
def test_client_secret_verified_true(
    mock_post_verify_secret: Mock,
    _api_url: str,
    _client_id: ClientId,
) -> None:
    secret_verifier = LettySecretVerifier(_api_url, _client_id)

    # Must be true as long as API call returns NO_CONTENT
    assert secret_verifier == "something"

    mock_post_verify_secret.assert_called_once()


@patch(
    "satosa_oidc_frontend.libraries.letty_api.api_session.post",
    return_value=Mock(status_code=HTTPStatus.UNAUTHORIZED),
)
def test_client_secret_verified_false(
    mock_post_verify_secret: Mock,
    _api_url: str,
    _client_id: ClientId,
) -> None:
    secret_verifier = LettySecretVerifier(_api_url, _client_id)

    # Must be false as long as API call returns anything but NO_CONTENT
    assert secret_verifier != "something"

    mock_post_verify_secret.assert_called_once()
