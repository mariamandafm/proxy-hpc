from copy import deepcopy
from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import patch

from satosa.internal import AuthenticationInformation
from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.helpers.config import Issuer
from coreaai_proxy_plugins.helpers.config import Requester
from coreaai_proxy_plugins.helpers.config import get_config_from_hierarchy
from coreaai_proxy_plugins.satosa.micro_services.elixir_stats_uploader import ElixirStatsUploader


class ElixirStatsUploaderTests(TestCase):
    def setUp(self):
        config = [
            {
                "user_id_attribute": "subject-id",
                "api_url": "https://elixir.example.org/api",
                "api_user": "api_user_name",
                "api_password": "api_pass_secret",
                "api_request_timeout": 2,
            },
            {
                "skip": True,
                "requester": "skip_for_this_requester",
                "user_id_attribute": "subject-id",
                "api_url": "https://elixir.example.org/api",
                "api_user": "api_user_name",
                "api_password": "api_pass_secret",
            },
            {
                "skip": True,
                "issuer": "skip_for_this_issuer",
                "user_id_attribute": "subject-id",
                "api_url": "https://elixir.example.org/api",
                "api_user": "api_user_name",
                "api_password": "api_pass_secret",
            },
        ]

        attributes = {
            "subject-id": ["satosa_user_identifier"],
        }

        data = InternalData(
            requester="service-to-be-processed",
            auth_info=AuthenticationInformation("", None, "issuer-user-authenticated-with"),
            attributes=attributes,
        )

        metadata = {
            "service-to-be-processed": {
                "display_name": "service to be processed display name"
            },
            "issuer-user-authenticated-with": {
                "display_name": "issuer user authenticated with display name"
            },
        }

        data.metadata = metadata
        context = Context()
        context.state = State()

        plugin = ElixirStatsUploader(
            config,
            name="ElixirStatsUploader",
            base_url="https://proxy.example.org",
        )
        plugin.next = lambda context, data: (context, data)

        self.attributes = deepcopy(attributes)
        self.config = config
        self.context = context
        self.data = data
        self.plugin = plugin

    @patch("coreaai_proxy_plugins.satosa.micro_services.elixir_stats_uploader.post_request")
    def test_user_auth_stats_uploaded_successfully(self, post_request_mock):
        post_request_mock.return_value = Mock(status_code=200)
        new_ctx, new_data = self.plugin.process(self.context, self.data)
        post_request_mock.assert_called_once()
        assert self.attributes == new_data.attributes


class ElixirStatsUploaderTestsErrorTests(TestCase):
    def setUp(self):
        config = [
            {
                "user_id_attribute": "uid",
                "api_url": "https://elixir.example.org/api",
                "api_user": "api_user_name",
                "api_password": "api_pass_secret",
                "api_request_timeout": 2,
            },
        ]

        attributes = {
            "uid": ["uid_value_from_idp", "another_uid_value_from_idp"],
        }

        metadata = {
            "service-to-be-processed": {
                "display_name": "service to be processed display name"
            },
            "issuer-user-authenticated-with": {
                "display_name": "issuer user authenticated with display name"
            },
        }

        context = Context()
        context.state = State()
        data = InternalData(
            requester="service-to-be-processed",
            auth_info=AuthenticationInformation("", None, "issuer-user-authenticated-with"),
            attributes=attributes,
        )
        data.metadata = metadata

        plugin = ElixirStatsUploader(
            config,
            name="ElixirStatsUploader",
            base_url="https://proxy.example.org",
        )
        plugin.next = lambda context, data: (context, data)

        self.attributes = deepcopy(attributes)
        self.config = config
        self.context = context
        self.data = data
        self.plugin = plugin

    @patch("coreaai_proxy_plugins.satosa.micro_services.elixir_stats_uploader.post_request")
    def test_user_id_missing(self, post_request_mock):
        requester = Requester(self.data.requester or "")
        issuer = Issuer(self.data.auth_info.issuer or "")
        config = get_config_from_hierarchy(self.plugin.config, requester, issuer)
        _ = self.data.attributes.pop(config.user_id_attribute, None)
        new_ctx, new_data = self.plugin.process(self.context, self.data)
        assert not post_request_mock.called
        assert not new_data.attributes

    @patch("coreaai_proxy_plugins.satosa.micro_services.elixir_stats_uploader.post_request")
    def test_request_failed(self, post_request_mock):
        post_request_mock.side_effect = Exception("Timeout")
        new_ctx, new_data = self.plugin.process(self.context, self.data)
        assert self.attributes == new_data.attributes

    @patch("coreaai_proxy_plugins.satosa.micro_services.elixir_stats_uploader.post_request")
    def test_response_status_not_200(self, post_request_mock):
        _ = self.data.metadata.get("service-to-be-processed").pop("display_name", None)
        post_request_mock.return_value = Mock(
            status_code=400,
            json=lambda: {
                "error": "serviceName is mandatory"
            },
        )
        new_ctx, new_data = self.plugin.process(self.context, self.data)
        assert self.attributes == new_data.attributes

    def test_unexpected_error(self):
        self.data.metadata = None
        new_ctx, new_data = self.plugin.process(self.context, self.data)
        assert self.attributes == new_data.attributes
