import unittest
from unittest.mock import patch

from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.attribute_checker import CheckerShortlist
from coreaai_proxy_plugins.satosa.micro_services.attribute_checker import CheckerError


STATE_KEY_MISSING_ATTRS = "missing_attributes"


class ConfigurationTests(unittest.TestCase):
    def test_empty_config(self):
        config = {}
        with self.assertRaises(CheckerError):
            CheckerShortlist(config, "name", "baseUrl")

    def test_missing_new_options(self):
        config = [
            {
                "api_base_url": "https://shortlist.example.org/api",
            }
        ]
        with self.assertRaises(CheckerError):
            CheckerShortlist(config, "name", "baseUrl")

    def test_ok_if_optional_options_missing(self):
        config = [
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "api_base_url": "https://shortlist.example.org/api",
                "api_key": "123",
            }
        ]
        assert CheckerShortlist(config, "name", "baseUrl")

    def test_ok_all_options(self):
        config = [
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "required_attributes": {"": ["edupersontargetedid"]},
                "redirect_url": "https://example.com",
                "api_base_url": "https://shortlist.example.org/api",
                "api_key": "123",
                "api_req_timeout": 5,
                "enable_addition_hook": False,
                "enable_removal_hook": True,
            }
        ]
        assert CheckerShortlist(config, "name", "baseUrl")


class DefaultTests(unittest.TestCase):
    def setUp(self):
        context = Context()
        context.state = State()
        self.context = context
        self.internal_data = InternalData(
            requester="requester-entity-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            metadata={
                "requester-entity-id": {
                    "display_name": "Example Services",
                    "contacts": [
                        {
                            "contact_type": "technical",
                            "given_name": "Technical",
                            "email_address": ["technical@example.com"],
                        },
                        {
                            "contact_type": "support",
                            "given_name": "Support",
                            "email_address": ["support@example.com"],
                        },
                        {
                            "contact_type": "other",
                            "given_name": "Security Response Team",
                            "email_address": ["mailto:security@example.com"],
                        },
                    ],
                },
                "issuer-entity-id": {
                    "display_name": "Example Identities",
                    "contacts": [
                        {
                            "contact_type": "technical",
                            "given_name": "Technical",
                            "email_address": ["technical@example.com"],
                        },
                        {
                            "contact_type": "support",
                            "given_name": "Support",
                            "email_address": ["support@example.com"],
                        },
                        {
                            "contact_type": "other",
                            "given_name": "Security Response Team",
                            "email_address": ["mailto:security@example.com"],
                        },
                    ],
                },
            },
        )

        self.config = [
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "api_base_url": "https://shortlist.example.org/api",
                "api_key": "123",
            },
        ]
        self.plugin = CheckerShortlist(self.config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.delete_request')
    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.post_request')
    def test_missing_required_attribute(self, req_post, req_delete):
        missing_attributes = ["required-but-missing"]
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        _ = self.plugin.process(self.context, self.internal_data)
        assert not req_post.called
        assert not req_delete.called

    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.delete_request')
    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.post_request')
    def test_no_missing_required_attribute(self, req_post, req_delete):
        missing_attributes = []
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        _ = self.plugin.process(self.context, self.internal_data)
        assert req_post.called
        assert not req_delete.called


class SpecificRequesterTests(unittest.TestCase):
    def setUp(self):
        context = Context()
        context.state = State()
        self.context = context
        self.internal_data = InternalData(
            requester="requester-entity-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            metadata={
                "requester-entity-id": {
                    "display_name": "Example Services",
                    "contacts": [
                        {
                            "contact_type": "technical",
                            "given_name": "Technical",
                            "email_address": ["technical@example.com"],
                        },
                        {
                            "contact_type": "support",
                            "given_name": "Support",
                            "email_address": ["support@example.com"],
                        },
                        {
                            "contact_type": "other",
                            "given_name": "Security Response Team",
                            "email_address": ["mailto:security@example.com"],
                        },
                    ],
                },
                "issuer-entity-id": {
                    "display_name": "Example Identities",
                    "contacts": [
                        {
                            "contact_type": "technical",
                            "given_name": "Technical",
                            "email_address": ["technical@example.com"],
                        },
                        {
                            "contact_type": "support",
                            "given_name": "Support",
                            "email_address": ["support@example.com"],
                        },
                        {
                            "contact_type": "other",
                            "given_name": "Security Response Team",
                            "email_address": ["mailto:security@example.com"],
                        },
                    ],
                },
            },
        )

        self.config = [
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "api_base_url": "https://shortlist.example.org/api",
                "api_key": "123",
            },
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "api_base_url": "https://shortlist.example.org/api",
                "api_key": "123",
                "enable_addition_hook": True,
                "enable_removal_hook": True,
                "requester": "requester-all-enabled",
            },
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "api_base_url": "https://shortlist.example.org/api",
                "api_key": "123",
                "requester": "requester-skip",
                "enable_addition_hook": True,
                "enable_removal_hook": True,
                "skip": True,
            },
        ]
        self.plugin = CheckerShortlist(self.config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.delete_request')
    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.post_request')
    def test_missing_but_skipped(self, req_post, req_delete):
        self.internal_data.requester = "requester-skip"
        missing_attributes = ["required-but-missing"]
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        _ = self.plugin.process(self.context, self.internal_data)
        assert not req_post.called
        assert not req_delete.called

    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.delete_request')
    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.post_request')
    def test_no_missing_but_skipped(self, req_post, req_delete):
        self.internal_data.requester = "requester-skip"
        missing_attributes = []
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        _ = self.plugin.process(self.context, self.internal_data)
        assert not req_post.called
        assert not req_delete.called

    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.delete_request')
    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.post_request')
    def test_missing_required_attribute(self, req_post, req_delete):
        self.internal_data.requester = "requester-all-enabled"
        missing_attributes = ["required-but-missing"]
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        _ = self.plugin.process(self.context, self.internal_data)
        assert not req_post.called
        assert req_delete.called

    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.delete_request')
    @patch('coreaai_proxy_plugins.satosa.micro_services.attribute_checker.shortlist.post_request')
    def test_no_missing_required_attribute(self, req_post, req_delete):
        self.internal_data.requester = "requester-all-enabled"
        missing_attributes = []
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        _ = self.plugin.process(self.context, self.internal_data)
        assert req_post.called
        assert not req_delete.called
