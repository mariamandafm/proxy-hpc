from copy import deepcopy
from json import loads as parse_json
from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import patch

from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.helpers.config import Issuer
from coreaai_proxy_plugins.helpers.config import Requester
from coreaai_proxy_plugins.helpers.config import get_config_from_hierarchy

from coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api import SBSAPIClient


class SBSAPIClientTests(TestCase):
    def setUp(self):
        api_to_internal_attributes = {
            "uid": "uid",
            "sshkey": "sshpublickey",
            "subject-id": "subject-id",
            "mail": "mail",
            "eduPersonEntitlement": "entitlement",
            "eduPersonPrincipalName": "eppn",
            "eduPersonUniqueID": "epuid",
        }

        config = [
            {
                "user_id_attribute": "subject-id",
                "user_email_attribute": "mail",
                "error_url": "https://service.example.org/error",
                "continue_url_state_key": "continue_url",
                "api_url": "https://sbs.example.org/api",
                "api_user": "api_user_name",
                "api_password": "api_pass_secret",
                "api_request_timeout": 2,
                "api_to_internal_attributes": api_to_internal_attributes,
            },
            {
                "skip": True,
                "requester": "skip_for_this_requester",
                "user_id_attribute": "subject-id",
                "user_email_attribute": "mail",
                "error_url": "https://service.example.org/error",
                "continue_url_state_key": "continue_url",
                "api_url": "https://sbs.example.org/api",
                "api_user": "api_user_name",
                "api_password": "api_pass_secret",
                "api_request_timeout": 2,
                "api_to_internal_attributes": api_to_internal_attributes,
            },
            {
                "skip": True,
                "issuer": "skip_for_this_issuer",
                "user_id_attribute": "subject-id",
                "user_email_attribute": "mail",
                "error_url": "https://service.example.org/error",
                "continue_url_state_key": "continue_url",
                "api_url": "https://sbs.example.org/api",
                "api_user": "api_user_name",
                "api_password": "api_pass_secret",
                "api_request_timeout": 2,
                "api_to_internal_attributes": api_to_internal_attributes,
            },
        ]

        attributes = {
            "epuid": ["value_from_idp_that_is_not_overridden"],
            "entitlement": ["should-be-gone"],
            "uid": ["uid_value_from_idp", "another_uid_value_from_idp"],
            "subject-id": ["satosa_user_identifier"],
            "mail": ["test-mail@example.org"],
        }

        metadata = {
            "service-to-be-processed": {
            },
            "registration_info": {
                "registration_authority": {
                    "": "not-surf-conext",
                }
            },
        }

        context = Context()
        context.state = State()
        data = InternalData(
            requester="service-to-be-processed",
            attributes=attributes,
        )
        data.metadata = metadata

        plugin = SBSAPIClient(
            config,
            name="SBSAPIClient",
            base_url="https://proxy.example.org",
        )
        plugin.next = lambda context, data: (context, data)

        self.attributes = deepcopy(attributes)
        self.config = config
        self.context = context
        self.data = data
        self.plugin = plugin

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_user_is_authorized_w_new_attributes(self, post_request_mock):
        response_attributes = {
            "eduPersonEntitlement": [
                "urn:mace:example.org:sram:group_a",
                "urn:mace:example.org:sram:group_b",
            ],
            "eduPersonPrincipalName": ["username@scope"],
            "uid": ["username"],
            "sshkey": ["ssh-key1", "ssh-key2"],
            "mail": ["test-mail@example.org"],
        }
        post_request_mock.return_value = Mock(
            status_code=200,
            json=lambda: {
                "status": {
                    "result": "authorized",
                },
                "attributes": response_attributes,
            },
        )

        new_ctx, new_data = self.plugin.process(self.context, self.data)

        post_request_mock.assert_called_once()
        assert self.attributes != new_data.attributes

        assert response_attributes.get("eduPersonUniqueID") is None
        assert self.attributes.get("sshpublickey") is None
        assert self.attributes["uid"] != response_attributes["uid"]
        assert (
            self.attributes["entitlement"]
            != response_attributes["eduPersonEntitlement"]
        )

        assert new_data.attributes["subject-id"] == self.attributes["subject-id"]
        assert new_data.attributes["mail"] == self.attributes["mail"]
        assert new_data.attributes["epuid"] == self.attributes["epuid"]
        assert new_data.attributes["sshpublickey"] == response_attributes["sshkey"]
        assert new_data.attributes["uid"] != self.attributes["uid"]
        assert new_data.attributes["uid"] == response_attributes["uid"]
        assert new_data.attributes["entitlement"] != self.attributes["entitlement"]
        assert (
            new_data.attributes["entitlement"]
            == response_attributes["eduPersonEntitlement"]
        )

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_user_is_authorized_w_new_attributes_invalid_values(
        self, post_request_mock
    ):
        entitlements = [
            "urn:mace:example.org:sram:group_a",
            "urn:mace:example.org:sram:group_b",
            "urn:mace:example.org:sram:group_invalid_\0_contains_nul",
        ]
        ssh_keys = [
            "ssh-key1",
            "ssh-key2",
            "ssh-key3-invalid_\b",
            "ssh-key4-invalid_\uFFFF",
        ]
        response_attributes = {
            "eduPersonEntitlement": entitlements,
            "eduPersonPrincipalName": ["username@scope"],
            "uid": ["username"],
            "sshkey": ssh_keys,
            "mail": ["test-mail@example.org"],
        }
        post_request_mock.return_value = Mock(
            status_code=200,
            json=lambda: {
                "status": {
                    "result": "authorized",
                },
                "attributes": response_attributes,
            },
        )

        new_ctx, new_data = self.plugin.process(self.context, self.data)

        post_request_mock.assert_called_once()
        assert self.attributes != new_data.attributes

        assert response_attributes.get("eduPersonUniqueID") is None
        assert self.attributes.get("sshpublickey") is None
        assert self.attributes["uid"] != response_attributes["uid"]
        assert self.attributes["entitlement"] != entitlements

        assert new_data.attributes["subject-id"] == self.attributes["subject-id"]
        assert new_data.attributes["epuid"] == self.attributes["epuid"]
        assert new_data.attributes["sshpublickey"] == ssh_keys[:-2]
        assert new_data.attributes["uid"] != self.attributes["uid"]
        assert new_data.attributes["uid"] == response_attributes["uid"]
        assert new_data.attributes["entitlement"] != self.attributes["entitlement"]
        assert new_data.attributes["entitlement"] == entitlements[:-1]

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_user_is_authorized_no_new_attributes(self, post_request_mock):
        response_attributes = {}
        post_request_mock.return_value = Mock(
            status_code=200,
            json=lambda: {
                "status": {
                    "result": "authorized",
                },
                "attributes": response_attributes,
            },
        )

        new_ctx, new_data = self.plugin.process(self.context, self.data)

        post_request_mock.assert_called_once()
        assert self.attributes == self.data.attributes == new_data.attributes
        assert response_attributes == {}

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_user_is_unauthorized(self, post_request_mock):
        response_status_redirect_url = "https://sbs.example.org/error"
        post_request_mock.return_value = Mock(
            status_code=200,
            json=lambda: {
                "status": {
                    "result": "unauthorized",
                    "redirect_url": response_status_redirect_url,
                },
            },
        )

        response = self.plugin.process(self.context, self.data)

        post_request_mock.assert_called_once()
        assert type(response) is Redirect
        assert dict(response.headers)["Location"] == response_status_redirect_url

    def test_service_is_skipped_due_to_requester(self):
        self.data.requester = "skip_for_this_requester"
        new_ctx, new_data = self.plugin.process(self.context, self.data)
        assert self.attributes == self.data.attributes == new_data.attributes

    def test_service_is_skipped_due_to_issuer(self):
        self.data.auth_info.issuer = "skip_for_this_issuer"
        new_ctx, new_data = self.plugin.process(self.context, self.data)
        assert self.attributes == self.data.attributes == new_data.attributes


class SBSAPIClientErrorTests(TestCase):
    def setUp(self):
        api_to_internal_attributes = {
            "uid": "uid",
            "sshkey": "sshpublickey",
            "subject-id": "subject-id",
            "mail": "mail",
            "eduPersonEntitlement": "entitlement",
            "eduPersonPrincipalName": "eppn",
            "eduPersonUniqueID": "epuid",
        }

        config = [
            {
                "user_id_attribute": "uid",
                "user_email_attribute": "mail",
                "error_url": "https://service.example.org/error",
                "continue_url_state_key": "continue_url",
                "api_url": "https://sbs.example.org/api",
                "api_user": "api_user_name",
                "api_password": "api_pass_secret",
                "api_request_timeout": 2,
                "api_to_internal_attributes": api_to_internal_attributes,
            },
        ]

        attributes = {
            "epuid": ["value_from_idp_that_is_not_overridden"],
            "entitlement": ["should-be-gone"],
            "uid": ["uid_value_from_idp", "another_uid_value_from_idp"],
            "mail": ["mail-test@example.org"],
        }

        metadata = {
            "service-to-be-processed": {
            },
            "registration_info": {
                "registration_authority": {
                    "": "not-surf-conext",
                }
            },
        }

        context = Context()
        context.state = State()
        data = InternalData(
            requester="service-to-be-processed",
            attributes=attributes,
        )
        data.metadata = metadata

        plugin = SBSAPIClient(
            config,
            name="SBSAPIClient",
            base_url="https://proxy.example.org",
        )
        plugin.next = lambda context, data: (context, data)

        self.attributes = deepcopy(attributes)
        self.config = config
        self.context = context
        self.data = data
        self.plugin = plugin

    def test_user_id_missing(self):
        requester = Requester(self.data.requester or "")
        issuer = Issuer(self.data.auth_info.issuer or "")
        config = get_config_from_hierarchy(self.plugin.config, requester, issuer)
        _ = self.data.attributes.pop(config.user_id_attribute, None)
        expected_redirect_url = config.error_url
        response = self.plugin.process(self.context, self.data)
        assert dict(response.headers)["Location"] == expected_redirect_url

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_request_failed(self, post_request_mock):
        requester = Requester(self.data.requester or "")
        issuer = Issuer(self.data.auth_info.issuer or "")
        config = get_config_from_hierarchy(self.plugin.config, requester, issuer)
        post_request_mock.side_effect = Exception("Timeout")
        expected_redirect_url = config.error_url
        response = self.plugin.process(self.context, self.data)
        assert dict(response.headers)["Location"] == expected_redirect_url

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_response_status_not_200(self, post_request_mock):
        requester = Requester(self.data.requester or "")
        issuer = Issuer(self.data.auth_info.issuer or "")
        config = get_config_from_hierarchy(self.plugin.config, requester, issuer)
        expected_redirect_url = config.error_url
        response_attributes = {}
        post_request_mock.return_value = Mock(
            status_code=400,
            json=lambda: {
                "status": {
                    "result": "authorized",
                },
                "attributes": response_attributes,
            },
        )
        response = self.plugin.process(self.context, self.data)
        post_request_mock.assert_called_once()
        assert dict(response.headers)["Location"] == expected_redirect_url

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_response_is_not_json(self, post_request_mock):
        requester = Requester(self.data.requester or "")
        issuer = Issuer(self.data.auth_info.issuer or "")
        config = get_config_from_hierarchy(self.plugin.config, requester, issuer)
        expected_redirect_url = config.error_url
        response_attributes = {}
        post_request_mock.return_value = Mock(
            status_code=200,
            json=lambda: parse_json(None),
        )
        response = self.plugin.process(self.context, self.data)
        post_request_mock.assert_called_once()
        assert dict(response.headers)["Location"] == expected_redirect_url

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_response_has_no_status_result(self, post_request_mock):
        requester = Requester(self.data.requester or "")
        issuer = Issuer(self.data.auth_info.issuer or "")
        config = get_config_from_hierarchy(self.plugin.config, requester, issuer)
        expected_redirect_url = config.error_url
        response_attributes = {}
        post_request_mock.return_value = Mock(
            status_code=400,
            json=lambda: {
                "status": {
                    "result_will_not_be_found": "authorized",
                },
                "attributes": response_attributes,
            },
        )
        response = self.plugin.process(self.context, self.data)
        post_request_mock.assert_called_once()
        assert dict(response.headers)["Location"] == expected_redirect_url

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_response_has_invalid_status_result(self, post_request_mock):
        requester = Requester(self.data.requester or "")
        issuer = Issuer(self.data.auth_info.issuer or "")
        config = get_config_from_hierarchy(self.plugin.config, requester, issuer)
        expected_redirect_url = config.error_url
        response_attributes = {}
        post_request_mock.return_value = Mock(
            status_code=200,
            json=lambda: {
                "status": {
                    "result": "invalid_status_result",
                },
                "attributes": response_attributes,
            },
        )
        response = self.plugin.process(self.context, self.data)
        post_request_mock.assert_called_once()
        assert dict(response.headers)["Location"] == expected_redirect_url

    @patch("coreaai_proxy_plugins.satosa.micro_services.sbs_authz_api.post_request")
    def test_unathorized_response_has_no_redirect_url(self, post_request_mock):
        requester = Requester(self.data.requester or "")
        issuer = Issuer(self.data.auth_info.issuer or "")
        config = get_config_from_hierarchy(self.plugin.config, requester, issuer)
        expected_redirect_url = config.error_url
        response_attributes = {}
        post_request_mock.return_value = Mock(
            status_code=200,
            json=lambda: {
                "status": {
                    "result": "unauthorized",
                    "redirect_url_will_not_be_found": "https://sbs.example.org/error",
                },
            },
        )
        response = self.plugin.process(self.context, self.data)
        post_request_mock.assert_called_once()
        assert dict(response.headers)["Location"] == expected_redirect_url
