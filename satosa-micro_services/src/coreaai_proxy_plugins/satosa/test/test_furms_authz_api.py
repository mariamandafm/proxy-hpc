import unittest
from unittest.mock import MagicMock, patch

from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.helpers.config import ConfigError
from coreaai_proxy_plugins.satosa.micro_services.furms_authz_api import (
    APIClient,
    APIClientError,
    Config,
    _authorize,
    _authorize_api_status,
    _authorize_api_status_and_local_user_id,
)


SP = "https://sp.example.org"
REDIRECT = "https://err.example.org/authz-error"
API_URL = "https://api.example.org/v1/{user_id}"
ENDPOINT = "https://api.example.org/v1/u1"
MODULE = "coreaai_proxy_plugins.satosa.micro_services.furms_authz_api"


def _config(**overrides):
    base = dict(
        attribute_identifier=["uid"],
        authz_strategy="authorize_status",
        redirect_url=REDIRECT,
        api_url=API_URL,
        api_user="user",
        api_password="pw",
        api_request_timeout=3,
        requester=None,
        issuer=None,
        skip=None,
    )
    base.update(overrides)
    return Config(**base)


def _entry(**overrides):
    entry = {
        "attribute_identifier": ["uid"],
        "authz_strategy": "authorize_status",
        "redirect_url": REDIRECT,
        "api_url": API_URL,
        "api_user": "user",
        "api_password": "pw",
    }
    entry.update(overrides)
    return entry


def _plugin(entries):
    plugin = APIClient(entries, "", "")
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context():
    context = Context()
    context.state = State()
    return context


def _response(status_code=200, json_data=None, text="", reason="OK", raise_json=False):
    response = MagicMock(status_code=status_code, text=text, reason=reason)
    if raise_json:
        response.json.side_effect = ValueError("not json")
    else:
        response.json.return_value = {} if json_data is None else json_data
    return response


class AuthorizeApiStatus(unittest.TestCase):
    @patch(f"{MODULE}.get_request")
    def test_authorized_status(self, mock_get):
        mock_get.return_value = _response(200, {"userStatus": "ENABLED"})

        result, data = _authorize_api_status(ENDPOINT, _config())

        self.assertTrue(result)
        self.assertEqual({"userStatus": "ENABLED"}, data)
        self.assertEqual(ENDPOINT, mock_get.call_args.args[0])
        self.assertEqual(3, mock_get.call_args.kwargs["timeout"])

    @patch(f"{MODULE}.get_request")
    def test_request_error_raises(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")

        with self.assertRaises(APIClientError):
            _authorize_api_status(ENDPOINT, _config())

    @patch(f"{MODULE}.get_request")
    def test_non_200_raises(self, mock_get):
        mock_get.return_value = _response(503, reason="Service Unavailable")

        with self.assertRaises(APIClientError):
            _authorize_api_status(ENDPOINT, _config())

    @patch(f"{MODULE}.get_request")
    def test_non_json_raises(self, mock_get):
        mock_get.return_value = _response(200, raise_json=True)

        with self.assertRaises(APIClientError):
            _authorize_api_status(ENDPOINT, _config())

    @patch(f"{MODULE}.get_request")
    def test_status_not_enabled_raises(self, mock_get):
        mock_get.return_value = _response(200, {"userStatus": "DISABLED"})

        with self.assertRaises(APIClientError):
            _authorize_api_status(ENDPOINT, _config())


class AuthorizeStatusAndLocalUserId(unittest.TestCase):
    @patch(f"{MODULE}.get_request")
    def test_authorized_with_local_ids(self, mock_get):
        doc = {
            "userStatus": "ENABLED",
            "siteAccess": [{"projectMemberships": [{"localUserId": "luid1"}]}],
        }
        mock_get.return_value = _response(200, doc)

        result, data = _authorize_api_status_and_local_user_id(ENDPOINT, _config())

        self.assertEqual(["luid1"], result)
        self.assertEqual(doc, data)

    @patch(f"{MODULE}.get_request")
    def test_no_local_ids_raises(self, mock_get):
        mock_get.return_value = _response(
            200, {"userStatus": "ENABLED", "siteAccess": []}
        )

        with self.assertRaises(APIClientError):
            _authorize_api_status_and_local_user_id(ENDPOINT, _config())


class AuthorizeDispatcher(unittest.TestCase):
    def test_no_user_ids_raises(self):
        data = InternalData(attributes={})

        with self.assertRaises(APIClientError):
            _authorize(_context(), data, _config())

    @patch(f"{MODULE}.get_request")
    def test_unknown_strategy_falls_back_to_default(self, mock_get):
        mock_get.return_value = _response(200, {"userStatus": "ENABLED"})
        data = InternalData(attributes={"uid": ["u1"]})

        self.assertTrue(_authorize(_context(), data, _config(authz_strategy="bogus")))

    @patch(f"{MODULE}.AUTHORIZATION_STRATEGIES")
    def test_falsy_results_complete_loop_without_authorizing(self, mock_strategies):
        # An authorizer that reports not-authorized without raising: the loop
        # tries every user id and returns None.
        mock_strategies.get.return_value = lambda url, config: (None, {})
        data = InternalData(attributes={"uid": ["u1", "u2"]})

        self.assertIsNone(_authorize(_context(), data, _config()))


class APIClientProcess(unittest.TestCase):
    def test_skip_passes_through(self):
        plugin = _plugin([_entry(skip=True)])
        data = InternalData(requester=SP, attributes={"uid": ["u1"]})

        _context_out, data_out = plugin.process(_context(), data)

        self.assertIs(data, data_out)

    def test_no_fallback_raises_config_error(self):
        plugin = _plugin([_entry(requester=SP)])
        data = InternalData(requester=SP, attributes={"uid": ["u1"]})

        with self.assertRaises(ConfigError):
            plugin.process(_context(), data)

    @patch(f"{MODULE}.get_request")
    def test_authorized_passes_through(self, mock_get):
        mock_get.return_value = _response(200, {"userStatus": "ENABLED"})
        plugin = _plugin([_entry()])
        data = InternalData(requester=SP, attributes={"uid": ["u1"]})

        result = plugin.process(_context(), data)

        self.assertNotIsInstance(result, Redirect)
        self.assertIs(data, result[1])

    @patch(f"{MODULE}.get_request")
    def test_unauthorized_redirects(self, mock_get):
        mock_get.return_value = _response(200, {"userStatus": "DISABLED"})
        plugin = _plugin([_entry()])
        data = InternalData(requester=SP, attributes={"uid": ["u1"]})

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(REDIRECT, result.message)

    def test_missing_identifier_redirects(self):
        plugin = _plugin([_entry()])
        data = InternalData(requester=SP, attributes={})

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(REDIRECT, result.message)

    @patch(f"{MODULE}._authorize")
    def test_generic_error_redirects(self, mock_authorize):
        mock_authorize.side_effect = ValueError("unexpected")
        plugin = _plugin([_entry()])
        data = InternalData(requester=SP, attributes={"uid": ["u1"]})

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(REDIRECT, result.message)


if __name__ == "__main__":
    unittest.main()
