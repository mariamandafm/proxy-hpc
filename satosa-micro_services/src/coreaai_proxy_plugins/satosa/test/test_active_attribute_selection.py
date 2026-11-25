import base64
import json
import unittest
from urllib import parse

from saml2.attribute_converter import ac_factory
from saml2.config import Config

from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.active_attribute_selection import (
    ActiveAttributeSelection,
)
from coreaai_proxy_plugins.satosa.micro_services.active_attribute_selection import (
    ActiveAttributeSelectionError,
)


class ActiveAttributeSelectionConfigurationTests(unittest.TestCase):
    def test_no_config(self):
        config = {}
        with self.assertRaises(ActiveAttributeSelectionError):
            ActiveAttributeSelection(config, "name", "baseUrl")

    def test_no_redirect_url(self):
        config = {
            "redirect_url": None,
            "selection_attributes": {"foo": ["bar"], "bar": ["foo"]},
            "endpoint": "foo",
        }
        with self.assertRaises(ActiveAttributeSelectionError):
            ActiveAttributeSelection(config, "name", "baseUrl")

    def test_no_selections(self):
        config = {
            "redirect_url": "https://example.com",
            "selection_attributes": {},
            "endpoint": "foo",
        }
        with self.assertRaises(ActiveAttributeSelectionError):
            ActiveAttributeSelection(config, "name", "baseUrl")

    def test_no_selections_inner_conf(self):
        config = {
            "redirect_url": "https://example.com",
            "selection_attributes": {
                "entity_id": {},
            },
            "endpoint": "foo",
        }
        with self.assertRaises(ActiveAttributeSelectionError):
            ActiveAttributeSelection(config, "name", "baseUrl")

    def test_no_endpoint(self):
        config = {
            "redirect_url": "https://example.com",
            "selection_attributes": {"foo": ["bar"], "bar": ["foo"]},
            "endpoint": None,
        }
        with self.assertRaises(ActiveAttributeSelectionError):
            ActiveAttributeSelection(config, "name", "baseUrl")

    def test_ok_config(self):
        config = {
            "redirect_url": "https://example.com",
            "selection_attributes": {"foo": {"foo": ["bar"]}, "bar": {"bar": ["foo"]}},
            "endpoint": "foo",
        }
        assert ActiveAttributeSelection(config, "name", "baseUrl")


class ActiveAttributeSelectionProcessTests(unittest.TestCase):
    def setUp(self):
        self.context = Context()
        self.context.state = State()

        self.internal_data = InternalData(
            requester="a-default-requester",
            auth_info=AuthenticationInformation("", None, "a-default-issuer"),
            metadata={"issuer-entity-id": {}},
        )

        self.config = {
            "redirect_url": "https://example.com",
            "selection_attributes": {
                "": {
                    "": ["epe", "epsa"],
                    "a-specific-requester": ["specific_value"]
                },
                "a-specific-issuer": {
                    "": ["epsa"],
                    "a-specific-requester": ["another_specific_value"]
                },
            },
            "endpoint": "handler",
        }
        self.plugin = ActiveAttributeSelection(self.config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

    def test_default_issuer_default_requester(self):
        expected = {
            "requester": "a-default-requester",
            "requester_name": "a default requester",
            "attributes": {"epe": ["some-value"], "epsa": ["some-value"]},
        }

        self.internal_data.attributes["epe"] = ["some-value"]
        self.internal_data.attributes["epsa"] = ["some-value"]
        self.internal_data.requester = "a-default-requester"
        self.internal_data.metadata = {
            "a-default-requester": {
                "display_name": "a default requester",
            }
        }
        response = self.plugin.process(self.context, self.internal_data)
        self.assertIsInstance(response, Redirect)

        redirect_url = response.message
        url_parts = parse.urlsplit(redirect_url)
        b64_data = url_parts.path.split("/")[-1]
        jdata = base64.urlsafe_b64decode(b64_data).decode("utf-8")
        data = json.loads(jdata)
        self.assertDictEqual(expected, data)

    def test_default_issuer_specific_requester(self):
        expected = {
            "requester": "a-specific-requester",
            "requester_name": "a specific requester",
            "attributes": {"specific_value": ["some-value"]},
        }

        self.internal_data.attributes["epe"] = ["some-value"]
        self.internal_data.attributes["specific_value"] = ["some-value"]
        self.internal_data.requester = "a-specific-requester"
        self.internal_data.metadata = {
            "a-specific-requester": {
                "display_name": "a specific requester"
            }
        }

        response = self.plugin.process(self.context, self.internal_data)
        self.assertIsInstance(response, Redirect)

        redirect_url = response.message
        url_parts = parse.urlsplit(redirect_url)
        b64_data = url_parts.path.split("/")[-1]
        jdata = base64.urlsafe_b64decode(b64_data).decode("utf-8")
        data = json.loads(jdata)
        self.assertDictEqual(expected, data)

    def test_specific_issuer_default_requester(self):
        expected = {
            "requester": "a-default-requester",
            "requester_name": "a default requester",
            "attributes": {"epsa": ["some-value"]},
        }

        self.internal_data.attributes["epe"] = ["some-value"]
        self.internal_data.attributes["epsa"] = ["some-value"]
        self.internal_data.requester = "a-default-requester"
        self.internal_data.auth_info.issuer = "a-specific-issuer"
        self.internal_data.metadata = {
            "a-default-requester": {
                "display_name": "a default requester",
            }
        }
        response = self.plugin.process(self.context, self.internal_data)
        self.assertIsInstance(response, Redirect)

        redirect_url = response.message
        url_parts = parse.urlsplit(redirect_url)
        b64_data = url_parts.path.split("/")[-1]
        jdata = base64.urlsafe_b64decode(b64_data).decode("utf-8")
        data = json.loads(jdata)
        self.assertDictEqual(expected, data)

    def test_specific_issuer_specific_issuer(self):
        expected = {
            "requester": "a-specific-requester",
            "requester_name": "a specific requester",
            "attributes": {"another_specific_value": ["some-value"]},
        }

        self.internal_data.attributes["epe"] = ["some-value"]
        self.internal_data.attributes["another_specific_value"] = ["some-value"]
        self.internal_data.requester = "a-specific-requester"
        self.internal_data.auth_info.issuer = "a-specific-issuer"
        self.internal_data.metadata = {
            "a-specific-requester": {
                "display_name": "a specific requester"
            }
        }

        response = self.plugin.process(self.context, self.internal_data)
        self.assertIsInstance(response, Redirect)

        redirect_url = response.message
        url_parts = parse.urlsplit(redirect_url)
        b64_data = url_parts.path.split("/")[-1]
        jdata = base64.urlsafe_b64decode(b64_data).decode("utf-8")
        data = json.loads(jdata)
        self.assertDictEqual(expected, data)


class ActiveAttributeSelectionEndpointTests(unittest.TestCase):
    def setUp(self):
        self.context = Context()
        self.context.internal_data = InternalData(
            requester="a-generic-requester",
            auth_info=AuthenticationInformation("", None, "a-default-issuer"),
            metadata={"issuer-entity-id": {}},
        )
        self.context.internal_data["requester"] = "a-generic-requester"

        self.context.state = State()
        self.context.state["AAS"] = {
            "internal_data": {
                "attributes": {
                    "epe": [
                        "test-epe",
                    ],
                    "epsa": ["test-epsa"],
                },
                "requester": "https://example.com",
            }
        }
        self.context.state["delete"] = False

        self.config = {
            "redirect_url": "https://example.com",
            "selection_attributes": {
                "":{
                    "": ["epe", "epsa"],
                    "a-specific-requester": ["epsa"],
                },
                "a-specific-issuer":{
                    "": ["epe", "epsa"],
                    "a-specific-requester": ["epe"],
                },
            },
            "endpoint": "handler",
        }
        self.plugin = ActiveAttributeSelection(self.config, "AAS", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

        self.context._path = "{endpoint}{payload}".format(
            endpoint=self.plugin.response_endpoint,
            payload=(
                "eyJhdHRyaWJ1dGVzIjogeyJlcGUiOiBbInVybjpnZWFudDpsaWZlc2NpZW5jZWlkLm9yZzpycy1zaXJ0ZmkiLCAidXJuOnJldGk6dGVzdGVyLm9yZzpycy1zaXJ0ZmkiXSwgImVwc2EiOiBbIm1lbWJlcnNAcmV0aS5pdCIsICJtZW1iZXJzQHZpc2NvLml0Il19fQ=="
            ),
        )

    def test_working_flow_no_selections(self):
        self.context._path = "{endpoint}{payload}".format(
            endpoint=self.plugin.response_endpoint,
            payload="eyJhdHRyaWJ1dGVzIjoge319",
        )
        expected_dict = {"epe": [], "epsa": []}
        self.context.internal_data.requester = "a-default-requester"
        self.context.internal_data.auth_info.issuer = "a-default-issuer"
        context, data = self.plugin._handle_response(self.context)
        self.assertDictEqual(data.attributes, expected_dict)

    def test_working_flow_one_selections(self):
        self.context._path = "{endpoint}{payload}".format(
            endpoint=self.plugin.response_endpoint,
            payload="eyJhdHRyaWJ1dGVzIjogeyJlcHNhIjogWyJ0ZXN0LWVwc2EiXX19",
        )
        expected_dict = {"epe": [], "epsa": ["test-epsa"]}
        context, data = self.plugin._handle_response(self.context)
        self.assertDictEqual(data.attributes, expected_dict)

    def test_working_flow_for_generic_issuer_generic_requester(self):
        self.context._path = "{endpoint}{payload}".format(
            endpoint=self.plugin.response_endpoint,
            payload=(
                "eyJhdHRyaWJ1dGVzIjogeyJlcGUiOiBbInRlc3QtZXBlIl0sICJlcHNhIjogWyJ0ZXN0LWVwc2EiXX19"
            ),
        )
        context, data = self.plugin._handle_response(self.context)
        expected_dict = {
            "epe": [
                "test-epe",
            ],
            "epsa": ["test-epsa"],
        }

        for attr_name in self.plugin.selection_attributes.get("").get(""):
            self.assertTrue(attr_name in data.attributes)

        for attr_name in self.plugin.selection_attributes.get("").get(""):
            self.assertEqual(
                sorted(expected_dict[attr_name]), sorted(data.attributes[attr_name])
            )

    def test_working_flow_with_inject_attribute(self):
        self.context._path = "{endpoint}{payload}".format(
            endpoint=self.plugin.response_endpoint,
            payload=(
                "eyJhdHRyaWJ1dGVzIjogeyJlcGUiOiBbIiB1cm46Z2VhbnQ6bGlmZXNjaWVuY2V"
                "pZC5vcmc6cnMtc2lydGZpIiwgIiB1cm46cmV0aTp0ZXN0ZXIub3JnOnJzLXNpcnRm"
                "aSJdLCAiZXBzYSI6IFsiIG1lbWJlcnNAcmV0aS5pdCIsICIgbWVtYmVyc0B2aXNjb"
                "y5pdCIsImluamVjdGVkQGF0dHJpYnV0ZS5vcmciXX19"
            ),
        )
        with self.assertRaises(ActiveAttributeSelectionError):
            self.plugin._handle_response(self.context)

    def test_working_flow_for_generic_issuer_specific_requester(self):
        self.context._path = "{endpoint}{payload}".format(
            endpoint=self.plugin.response_endpoint,
            payload=(
                "eyJhdHRyaWJ1dGVzIjogeyJlcHNhIjogWyJ0ZXN0LWVwc2EiXX19"
            )
        )
        requester = "a-specific-requester"
        self.context.internal_data["requester"] = requester
        context, data = self.plugin._handle_response(self.context)
        self.assertTrue(
            all(
                attribute in data.attributes
                for attribute in self.plugin.selection_attributes.get("").get(requester)
            )
        )

    def test_working_flow_for_specific_issuer_generic_requester(self):
        self.context._path = "{endpoint}{payload}".format(
            endpoint=self.plugin.response_endpoint,
            payload=(
                "eyJhdHRyaWJ1dGVzIjogeyJlcGUiOiBbInRlc3QtZXBlIl0sICJlcHNhIjogWyJ0ZXN0LWVwc2EiXX19"
            ),
        )
        context, data = self.plugin._handle_response(self.context)
        expected_dict = {
            "epe": [
                "test-epe",
            ],
            "epsa": ["test-epsa"],
        }
        self.context.internal_data.requester = "a-default-requester"
        self.context.internal_data.auth_info.issuer = "a-specific-issuer"

        for attr_name in self.plugin.selection_attributes.get("").get(""):
            self.assertTrue(attr_name in data.attributes)

        for attr_name in self.plugin.selection_attributes.get("").get(""):
            self.assertEqual(
                sorted(expected_dict[attr_name]), sorted(data.attributes[attr_name])
            )

    def test_working_flow_for_specific_issuer_specific_requester(self):
        self.context._path = "{endpoint}{payload}".format(
            endpoint=self.plugin.response_endpoint,
            payload=(
                "eyJhdHRyaWJ1dGVzIjogeyJlcGUiOiBbInRlc3QtZXBlIl19fQ=="
            )
        )
        self.context.internal_data.requester = "a-specific-requester"
        self.context.internal_data.auth_info.issuer = "a-specific-issuer"
        requester = "a-specific-requester"
        self.context.internal_data["requester"] = requester
        context, data = self.plugin._handle_response(self.context)
        self.assertTrue(
            all(
                attribute in data.attributes
                for attribute in self.plugin.selection_attributes.get("a-specific-issuer").get(requester)
            )
        )

    def test_wrong_path(self):
        self.context._path = "DEFINITELYAWRONGPATH"
        self.plugin = ActiveAttributeSelection(self.config, "name", "baseUrl")
        with self.assertRaises(ActiveAttributeSelectionError):
            self.plugin._handle_response(self.context)


if __name__ == "__main__":
    unittest.main()
