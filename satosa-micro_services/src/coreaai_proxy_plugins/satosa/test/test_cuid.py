import json
import unittest
import base64
import copy
import time
import requests
from urllib import parse
from unittest.mock import Mock
from unittest.mock import patch

from saml2.attribute_converter import ac_factory
from saml2.config import Config

from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.cuid import CUIDClient
from coreaai_proxy_plugins.satosa.micro_services.cuid import CUIDError
from coreaai_proxy_plugins.helpers.config import parse_config

config = {
    "issuer": {
        "requester": {
            "access_token": "random-string",
            "api_endpoint": "https://proxy/cuid/",
            "api_req_timeout": 2,
            "iuid_attribute": "vopersonexternalid",
            "cuid_attribute": "subject_id",
            "scope": "example.org",
            "disabled": False,
        }
    }
}


class CUIDClientConfigurationTests(unittest.TestCase):

    CONFIG = {
        "default": {
            "default": {
                "access_token": "random-string",
                "api_endpoint": "https://localhost/cuid/",
                "api_req_timeout": 5,
                "iuid_attribute": "vopersonexternalid",
                "cuid_attribute": "subject_id",
                "scope": "example.org",
                "disabled": False,
            }
        }
    }

    def test_empty_config(self):
        config = {}
        CUIDClient(config, "", "")

    def test_disabled_config(self):
        config = {"default": {"default": {"disabled": True}}}
        CUIDClient(config, "", "")

    def test_missing_requester(self):
        config = self.CONFIG.copy()
        config["default"] = self.CONFIG["default"]["default"].copy()

        with self.assertRaises(CUIDError):
            CUIDClient(config, "", "")

    def test_missing_or_wrong_access_token(self):
        config = copy.deepcopy(self.CONFIG)
        del config["default"]["default"]["access_token"]
        with self.assertRaises(CUIDError):
            CUIDClient(config, "", "")

        for value in ["", 12345, None, False]:
            config["default"]["default"]["access_token"] = value
            with self.assertRaises(CUIDError):
                CUIDClient(config, "", "")

    def test_missing_or_wrong_api_endpoint(self):
        config = copy.deepcopy(self.CONFIG)
        del config["default"]["default"]["api_endpoint"]
        with self.assertRaises(CUIDError):
            CUIDClient(config, "", "")

        for value in ["http", 12345, None, False, "not-a-valid-url"]:
            config["default"]["default"]["api_endpoint"] = value
            with self.assertRaises(CUIDError):
                CUIDClient(config, "", "")

    def test_missing_or_wrong_api_req_timeout(self):
        config = copy.deepcopy(self.CONFIG)
        del config["default"]["default"]["api_req_timeout"]
        CUIDClient(config, "", "")

        for value in ["", None, False, "string"]:
            config["default"]["default"]["api_req_timeout"] = value
            with self.assertRaises(CUIDError):
                CUIDClient(config, "", "")

    def test_missing_or_wrong_iuid_attribute(self):
        config = copy.deepcopy(self.CONFIG)
        del config["default"]["default"]["iuid_attribute"]
        with self.assertRaises(CUIDError):
            CUIDClient(config, "", "")

        for value in ["", None, False, 12345]:
            config["default"]["default"]["iuid_attribute"] = value
            with self.assertRaises(CUIDError):
                CUIDClient(config, "", "")

    def test_missing_or_wrong_cuid_attribute(self):
        config = copy.deepcopy(self.CONFIG)
        del config["default"]["default"]["cuid_attribute"]
        with self.assertRaises(CUIDError):
            CUIDClient(config, "", "")

        for value in ["", None, False, 12345]:
            config["default"]["default"]["cuid_attribute"] = value
            with self.assertRaises(CUIDError):
                CUIDClient(config, "", "")

    def test_wrong_scope(self):
        config = copy.deepcopy(self.CONFIG)

        for value in [None, False, 12345]:
            config["default"]["default"]["scope"] = value
            with self.assertRaises(CUIDError):
                CUIDClient(config, "", "")

    def test_multiple_requesters_wrong_config(self):
        config = copy.deepcopy(self.CONFIG)
        config["issuer"] = {
            "requester": {
                "disabled": False,
            }
        }
        with self.assertRaises(CUIDError):
            CUIDClient(config, "", "")

    def test_multiple_isssuers_requesters_wrong_config(self):
        config = copy.deepcopy(self.CONFIG)
        config["issuer1"] = copy.deepcopy(self.CONFIG["default"])
        config["issuer1"]["requester1"] = copy.deepcopy(
            self.CONFIG["default"]["default"]
        )
        config["issuer2"] = {
            "requester1": {
                "disabled": False,
            }
        }
        with self.assertRaises(CUIDError):
            CUIDClient(config, "", "")


class CUIDClientDefaultTests(unittest.TestCase):
    def setUp(self):
        context = Context()
        context.state = State()
        self.context = context
        self.internal_data = InternalData(
            requester="a-requester-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            attributes={"vopersonexternalid": ["id-123"]},
            metadata={},
        )

        self.config = {
            "default": {
                "default": {
                    "access_token": "random-string",
                    "api_endpoint": "https://localhost/cuid/",
                    "api_req_timeout": 5,
                    "iuid_attribute": "vopersonexternalid",
                    "cuid_attribute": "subject_id",
                    "scope": "example.org",
                    "disabled": False,
                }
            }
        }

        self.plugin = CUIDClient(self.config, "", "")
        self.plugin.next = lambda context, data: (context, data)
        requester = self.internal_data.requester
        issuer = self.internal_data.auth_info.issuer
        parsed_config = parse_config(self.config, issuer, requester)

        self.parsed_config = (
            parsed_config["by-iss-req"]
            if isinstance(parsed_config["by-iss-req"], dict)
            else parsed_config["by-req-iss"]
            if isinstance(parsed_config["by-req-iss"], dict)
            else parsed_config["by-requester"]
            if isinstance(parsed_config["by-requester"], dict)
            else parsed_config["by-issuer"]
            if isinstance(parsed_config["by-issuer"], dict)
            else {}
        )

    @patch("requests.post")
    def test_connection_error(self, mocked_post):

        internal_data = InternalData(
            requester="a-requester-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            attributes={"vopersonexternalid": ["id-123"]},
            metadata={},
        )

        exceptions = [
            requests.ConnectTimeout(),
            requests.Timeout(),
            requests.ReadTimeout(),
            requests.HTTPError(),
        ]

        for exception in exceptions:

            mocked_post.side_effect = exception
            mocked_post.return_value = Mock(
                status_code=200,
                json=lambda: {"cuid": "2737107B-2E20-438F-9333-4F8021E44CC8"},
            )

            with self.assertRaises(CUIDError):
                self.plugin.process(self.context, internal_data)

    @patch("requests.post")
    def test_http_request(self, mocked_post):
        internal_data = InternalData(
            requester="a-requester-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            attributes={"vopersonexternalid": ["id-123"]},
            metadata={},
        )

        mocked_post.return_value = Mock(
            status_code=201,
            json=lambda: {"cuid": "E9EA15E6-FBE4-47AB-BB17-085AB1FD37BC"},
        )

        self.plugin.process(self.context, internal_data)

        mocked_post.assert_called_with(
            self.parsed_config["api_endpoint"],
            params={"access_token": self.parsed_config["access_token"]},
            json=internal_data["attributes"].get(self.parsed_config["iuid_attribute"]),
            timeout=self.parsed_config["api_req_timeout"],
        )

    def test_no_iuids(self):

        internal_data = InternalData(
            requester="a-requester-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            attributes={},
            metadata={},
        )

        with self.assertRaises(CUIDError):
            self.plugin.process(self.context, internal_data)

    @patch("requests.post")
    def test_multiple_cuids(self, mocked_post):

        internal_data = InternalData(
            requester="a-requester-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            attributes={"vopersonexternalid": ["id-123"]},
            metadata={},
        )

        mocked_post.return_value = Mock(
            status_code=409, json=lambda: {"detail": "Multiple CUIDs found"}
        )

        with self.assertRaises(CUIDError):
            self.plugin.process(self.context, internal_data)
            assert mocked_post.called

    @patch("requests.post")
    def test_new_cuid(self, mocked_post):

        internal_data = InternalData(
            requester="a-requester-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            attributes={"vopersonexternalid": ["id-123"]},
            metadata={},
        )

        mocked_post.return_value = Mock(
            status_code=201,
            json=lambda: {"cuid": "E9EA15E6-FBE4-47AB-BB17-085AB1FD37BC"},
        )
        self.plugin.process(self.context, internal_data)

        assert mocked_post.called
        self.assertNotEqual(internal_data, self.internal_data)
        self.assertEqual(
            internal_data["attributes"][self.parsed_config["cuid_attribute"]],
            [f"E9EA15E6-FBE4-47AB-BB17-085AB1FD37BC@{self.parsed_config['scope']}"],
        )

    @patch("requests.post")
    def test_existing_cuid(self, mocked_post):

        internal_data = InternalData(
            requester="a-requester-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
            attributes={"vopersonexternalid": ["id-123"]},
            metadata={},
        )

        mocked_post.return_value = Mock(
            status_code=200,
            json=lambda: {"cuid": "2737107B-2E20-438F-9333-4F8021E44CC8"},
        )
        self.plugin.process(self.context, internal_data)

        assert mocked_post.called
        self.assertNotEqual(internal_data, self.internal_data)
        self.assertEqual(
            internal_data["attributes"][self.parsed_config["cuid_attribute"]],
            [f"2737107B-2E20-438F-9333-4F8021E44CC8@{self.parsed_config['scope']}"],
        )


if __name__ == "__main__":
    unittest.main()
