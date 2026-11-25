import json
from logging import warn
import unittest
import base64
from urllib import parse

from saml2.attribute_converter import ac_factory
from saml2.config import Config

from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.attribute_checker import CheckerRedirect
from coreaai_proxy_plugins.satosa.micro_services.attribute_checker import CheckerError


STATE_KEY_MISSING_ATTRS = "missing_attributes"


class ConfigurationTests(unittest.TestCase):
    def test_empty_config(self):
        config = {}
        with self.assertRaises(CheckerError):
            CheckerRedirect(config, "name", "baseUrl")

    def test_missing_redirect_url(self):
        config = {"foo": {}}
        with self.assertRaises(CheckerError):
            CheckerRedirect(config, "name", "baseUrl")


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
                "redirect_url": "https://example.com",
            },
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "redirect_url": "https://example.com",
                "requester": "https://example.com/sp",
                "skip": True,
            },
        ]
        self.plugin = CheckerRedirect(self.config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

    def test_missing_required_attribute(self):
        missing_attributes = ["required-but-missing"]
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        expected = {
            "requester": "requester-entity-id",
            "requester_name": "Example Services",
            "issuer": "issuer-entity-id",
            "issuer_name": "Example Identities",
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
            "missing_attributes": missing_attributes,
        }

        response = self.plugin.process(self.context, self.internal_data)
        self.assertIsInstance(response, Redirect)

        redirect_url = response.message
        url_parts = parse.urlsplit(redirect_url)
        b64_data = url_parts.path.split("/")[-1]
        jdata = base64.urlsafe_b64decode(b64_data).decode("utf-8")
        data = json.loads(jdata)
        self.assertDictEqual(expected, data)

    def test_no_missing_required_attribute(self):
        missing_attributes = []
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        result = self.plugin.process(self.context, self.internal_data)
        self.assertNotIsInstance(result, Redirect)


class SpecificRequesterTests(unittest.TestCase):
    def setUp(self):
        context = Context()
        context.state = State()
        self.context = context
        self.internal_data = InternalData(
            requester="requester-entity-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            metadata={
                "requester-other-location": {
                    "display_name": "Example Other Services",
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
                "redirect_url": "https://example.com",
            },
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "redirect_url": "https://example.com/otherlocaltion",
                "requester": "requester-other-location",
            },
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "redirect_url": "https://example.com",
                "requester": "requester-skip",
                "skip": True,
            },
        ]
        self.plugin = CheckerRedirect(self.config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

    def test_skipped(self):
        self.internal_data.requester = "requester-skip"
        missing_attributes = ["required-but-missing"]
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        result = self.plugin.process(self.context, self.internal_data)
        self.assertNotIsInstance(result, Redirect)

    def test_other_location(self):
        self.internal_data.requester = "requester-other-location"
        missing_attributes = ["required-but-missing"]
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        expected = {
            "requester": "requester-other-location",
            "requester_name": "Example Other Services",
            "issuer": "issuer-entity-id",
            "issuer_name": "Example Identities",
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
            "missing_attributes": missing_attributes,
        }

        response = self.plugin.process(self.context, self.internal_data)
        self.assertIsInstance(response, Redirect)

        redirect_url = response.message
        url_parts = parse.urlsplit(redirect_url)
        location = url_parts.path.split("/")[1]
        self.assertEqual(location, "otherlocaltion")

        b64_data = url_parts.path.split("/")[-1]
        jdata = base64.urlsafe_b64decode(b64_data).decode("utf-8")
        data = json.loads(jdata)
        self.assertDictEqual(expected, data)

    def test_no_missing_required_attribute(self):
        missing_attributes = []
        self.context.state[STATE_KEY_MISSING_ATTRS] = missing_attributes
        result = self.plugin.process(self.context, self.internal_data)
        self.assertNotIsInstance(result, Redirect)
