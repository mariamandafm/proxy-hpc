import warnings
from typing import Callable, Generator, Optional
from unittest.mock import patch

import pytest
from satosa.context import Context
from satosa_oidc_frontend.frontend import OpenIDConnectFrontend
from satosa_oidc_frontend.libraries.letty_api import (
    LettyClientsAPI,
    UnsupportedLettyOperation,
)
from tests.frontend.test_frontend import CLIENT_ID, CLIENT_SECRET, EXTRA_SCOPES, JWKS
from tests.frontend.test_frontend import (
    TestAudiencePolicies as _TestAudiencePolicies,  # Prefix with _ so pytest won't consider read it as a separate test class
)
from tests.frontend.test_frontend import (
    TestOpenIDConnectFrontend as _TestOpenIDConnectFrontend,  # Prefix with _ so pytest won't consider read it as a separate test class
)
from tests.frontend.test_frontend import (
    TestOpenIDConnectFrontendDB as _TestOpenIDConnectFrontendDB,  # Prefix with _ so pytest won't consider read it as a separate test class
)
from tests.frontend.test_frontend import (
    TestRemoteDataProviderInfo as _TestRemoteDataProviderInfo,  # Prefix with _ so pytest won't consider read it as a separate test class
)
from tests.frontend.test_frontend import (
    TestRemoteIntrospection as _TestRemoteIntrospection,  # Prefix with _ so pytest won't consider read it as a separate test class
)
from tests.frontend.test_frontend import response_types_supported


@pytest.fixture
def supported_letty_fields() -> set[str]:
    """
    List of fields that are currently supported when retrieving clients from Letty
    """

    return {
        "client_id",
        "client_secret",
        "client_name",
        "client_uri",
        "organization_name",
        "organization_website",
        "service_description",
        "policy_uri",
        "tos_uri",
        "grant_types_supported",
        "allowed_scopes",
        "response_types_supported",
        "token_endpoint_client_authn_method",
        "introspection_endpoint_client_authn_method",
        "pkce_essential",
        "redirect_uris",
        "application_type",
        "token_usage_rules",
        "revoke_refresh_on_issue",
    }


@pytest.fixture
def temp_client_db() -> dict:
    return dict()


@pytest.fixture
def insert_client(temp_client_db, supported_letty_fields) -> Callable:
    def _insert_client(
        frontend: dict,
        redirect_uri: str,
        client_id: str = CLIENT_ID,
        client_secret: str = CLIENT_SECRET,
        extra_metadata: Optional[dict] = None,
    ) -> None:
        client_info = {
            "response_types_supported": response_types_supported,
            "redirect_uris": [(redirect_uri, "")],
            "client_secret": client_secret,
            "allowed_scopes": [
                "openid",
                "email",
                "offline_access",
                "eduperson",
            ],
            **(extra_metadata or {}),
        }

        unsupported_fields = client_info.keys() - supported_letty_fields
        if unsupported_fields:
            warnings.warn(f"Unsupported fields in Letty: {unsupported_fields}")

        temp_client_db[client_id] = client_info

    return _insert_client


@pytest.fixture(autouse=True)
def patch_letty(temp_client_db) -> Generator:
    LettyClientsAPI._get_and_cache_info_by_client_id.cache_clear()

    _letty_get_client_patch = patch.object(
        LettyClientsAPI, "_get_and_cache_info_by_client_id"
    )
    _mock_get_client = _letty_get_client_patch.start()
    _mock_get_client.side_effect = lambda _api_url, client_id: temp_client_db.get(
        client_id
    )

    yield

    _letty_get_client_patch.stop()


@pytest.fixture
def frontend_config_with_letty() -> dict:
    return {
        "client_db_handler_class_path": "satosa_oidc_frontend.libraries.letty_api.LettyClientsAPI",
        "client_db_handler_class_kwargs": {"api_url": "http://test.letty.org/api"},
        "client_db_enable_import": False,
    }


@pytest.fixture
def frontend_config(frontend_config_with_letty) -> dict:
    # Use same config as TestOpenIDConnectFrontendDB except for client DB config
    return {
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
    } | frontend_config_with_letty


@pytest.fixture
def frontend_config_extra_scopes(frontend_config: dict) -> dict:
    return frontend_config | {
        "allowed_scopes": ["openid", "email", "offline_access", "eduperson"],
        "scopes_to_claims": EXTRA_SCOPES,
    }


class TestOpenIDConnectFrontend(_TestOpenIDConnectFrontend):
    @pytest.mark.xfail(raises=UnsupportedLettyOperation)
    def test_handle_registration(
        self,
        context: Context,
        frontend: OpenIDConnectFrontend,
        authn_req: dict,
        insert_client: Callable,
    ):
        _TestOpenIDConnectFrontend.test_handle_registration(
            self, context, frontend, authn_req, insert_client
        )

    @pytest.mark.parametrize("has_attributes", [True, False])
    def test_handle_authenticated_attribute_registration(
        self,
        context: Context,
        frontend_config_extra_scopes: dict,
        authn_req: dict,
        attribute_auth_config: dict,
        has_attributes: bool,
        insert_client: Callable,
    ):
        try:
            _TestOpenIDConnectFrontend.test_handle_authenticated_attribute_registration(
                self,
                context,
                frontend_config_extra_scopes,
                authn_req,
                attribute_auth_config,
                has_attributes,
                insert_client,
            )
        except UnsupportedLettyOperation:
            # If `has_attributes` is True, Letty will raise an error
            assert has_attributes
        else:
            # If `has_attributes` is False, Letty will not be called at all
            assert not has_attributes

    @pytest.mark.xfail(raises=UnsupportedLettyOperation)
    def test_register_client(
        self,
        context: Context,
        frontend: OpenIDConnectFrontend,
        authn_req: dict,
        insert_client: Callable,
    ):
        _TestOpenIDConnectFrontend.test_register_client(
            self, context, frontend, authn_req, insert_client
        )

    @pytest.mark.xfail(raises=UnsupportedLettyOperation)
    def test_register_client_many_resp_types(
        self,
        context: Context,
        frontend: OpenIDConnectFrontend,
        authn_req: dict,
        insert_client: Callable,
    ):
        _TestOpenIDConnectFrontend.test_register_client_many_resp_types(
            self, context, frontend, authn_req, insert_client
        )

    @pytest.mark.xfail(raises=UnsupportedLettyOperation)
    def test_register_client_with_wrong_response_type(
        self,
        context: Context,
        frontend_config: dict,
        authn_req: dict,
        insert_client: Callable,
    ):
        _TestOpenIDConnectFrontend.test_register_client_with_wrong_response_type(
            self, context, frontend_config, authn_req, insert_client
        )

    @pytest.mark.xfail(raises=UnsupportedLettyOperation)
    def test_registration_request_method(
        self,
        context: Context,
        frontend: OpenIDConnectFrontend,
        authn_req: dict,
        insert_client: Callable,
    ):
        _TestOpenIDConnectFrontend.test_registration_request_method(
            self, context, frontend, authn_req, insert_client
        )

    @pytest.mark.parametrize("overwrite_clients_in_db", [True, False])
    def test_clients_json_overwrite(
        self,
        context: Context,
        frontend_config: dict,
        authn_req: dict,
        overwrite_clients_in_db: bool,
        insert_client: Callable,
    ):
        try:
            _TestOpenIDConnectFrontend.test_clients_json_overwrite(
                self,
                context,
                frontend_config,
                authn_req,
                overwrite_clients_in_db,
                insert_client,
            )
        except UnsupportedLettyOperation:
            # If `overwrite_clients_in_db` is True, Letty will raise an error
            assert overwrite_clients_in_db
        else:
            # If `overwrite_clients_in_db` is False, Letty will not be called at all
            assert not overwrite_clients_in_db


class TestOpenIDConnectFrontendDB(
    _TestOpenIDConnectFrontendDB,
    TestOpenIDConnectFrontend,
):
    @pytest.fixture
    def frontend_config(self, frontend_config_with_letty):
        return {
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
        } | frontend_config_with_letty

    @pytest.fixture
    def frontend_config_extra_scopes(self, frontend_config):
        return frontend_config | {
            "allowed_scopes": ["openid", "email", "offline_access", "eduperson"],
            "scopes_to_claims": EXTRA_SCOPES,
        }


class TestRemoteIntrospection(_TestRemoteIntrospection):
    @pytest.fixture
    def frontend_config(self, remote_introspection_config, frontend_config_with_letty):
        return {
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
        } | frontend_config_with_letty


class TestAudiencePolicies(_TestAudiencePolicies):
    @pytest.fixture
    def frontend_config(self, frontend_config_with_letty):
        return {
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
        } | frontend_config_with_letty


class TestRemoteDataProviderInfo(_TestRemoteDataProviderInfo):
    @pytest.fixture
    def frontend_config(self, remote_data_provider_config, frontend_config_with_letty):
        return {
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
        } | frontend_config_with_letty
