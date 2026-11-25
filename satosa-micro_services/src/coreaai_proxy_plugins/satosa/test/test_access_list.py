import json
import unittest
from urllib import parse

from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.access_list import AccessList
from coreaai_proxy_plugins.satosa.micro_services.access_list import AccessListError
from coreaai_proxy_plugins.satosa.micro_services.access_list import IssuerAccessList
from coreaai_proxy_plugins.satosa.micro_services.access_list import RequesterAccessList


class AccessListConfigurationTests(unittest.TestCase):
    def test_init_function_no_config(self):
        config = {}
        with self.assertRaises(AccessListError):
            RequesterAccessList(config, "name", "baseUrl")

    def test_init_function_config_missing_access_list(self):
        config = {"redirect_url": "https://example.org"}
        with self.assertRaises(AccessListError):
            RequesterAccessList(config, "name", "baseUrl")

    def test_init_function_config_missing_redirect_url(self):
        config = {"access_list": ["example_requester"]}
        with self.assertRaises(AccessListError):
            RequesterAccessList(config, "name", "baseUrl")

    def test_init_function_config_invalid_redirect_url_type(self):
        config = {"access_list": ["example_requester"], "redirect_url": [None]}
        with self.assertRaises(AccessListError):
            RequesterAccessList(config, "name", "baseUrl")

    def test_init_function_config_empty_access_list(self):
        config = {"access_list": [], "redirect_url": "https://example.org"}
        with self.assertRaises(AccessListError):
            RequesterAccessList(config, "name", "baseUrl")


class RequesterAccessListAuthorizedTests(unittest.TestCase):
    def setUp(self):
        config = {
            "redirect_url": "https://example.org",
            "access_list": ["example_requester"],
        }
        self.plugin = RequesterAccessList(config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        self.context = context
        self.internal_data = InternalData(requester="example_requester")

    def test_process_authorized(self):
        result = self.plugin.process(self.context, self.internal_data)
        assert type(result) is tuple
        assert len(result) == 2


class RequesterAccessListUnAuthorizedTests(unittest.TestCase):
    def setUp(self):
        config = {
            "redirect_url": "https://example.org",
            "access_list": ["example_requester"],
        }
        self.plugin = RequesterAccessList(config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        self.context = context
        self.internal_data = InternalData(
            requester="example_requester_unauthorized", requester_name=""
        )

    def test_process_unauthorized(self):
        response = self.plugin.process(self.context, self.internal_data)
        self.assertIsInstance(response, Redirect)

        expected = {"requester": "example_requester_unauthorized", "requester_name": ""}
        redirect_url = response.message
        url_parts = parse.urlsplit(redirect_url)
        query_string = url_parts.query
        query_data = parse.parse_qs(query_string)
        data_param = query_data["data"][0]
        data = json.loads(data_param)
        self.assertDictEqual(expected, data)


if __name__ == "__main__":
    unittest.main()
