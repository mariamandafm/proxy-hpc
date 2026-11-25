import unittest
from unittest.mock import MagicMock, patch

from satosa.context import Context
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.helpers.config import ConfigError as ResolveConfigError
from coreaai_proxy_plugins.helpers.grove.scim import SCIMError
from coreaai_proxy_plugins.satosa.micro_services.grove_accounts import (
    ConfigError,
    CreateGroveAccount,
    Error,
    _needs_update,
    _normalize_email_list,
    _process_create_account,
)


SP = "https://sp.example.org"
IDP = "https://idp.example.org"
ERROR_URL = "https://err.example.org/error"
MODULE = "coreaai_proxy_plugins.satosa.micro_services.grove_accounts"


def _entry(**overrides):
    entry = dict(
        grove_api_url="https://grove.example.org",
        grove_api_token="token",
        error_url=ERROR_URL,
        error_on_missing_attrs=False,
        attr_internal_cuid="cuid",
        attr_internal_first_name="first_name",
        attr_internal_last_name="last_name",
        attr_internal_email="email",
    )
    entry.update(overrides)
    return entry


def _build_plugin(entries):
    plugin = CreateGroveAccount(entries, "", "")
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context():
    context = Context()
    context.state = State()
    return context


def _data(attributes=None, requester=SP, issuer=IDP):
    return InternalData(
        auth_info=AuthenticationInformation("", None, issuer),
        requester=requester,
        attributes=attributes if attributes is not None else {},
    )


def _full_attrs():
    return {
        "cuid": ["cuid-1"],
        "first_name": ["First"],
        "last_name": ["Last"],
        "email": ["u@example.org"],
    }


class NormalizeEmailList(unittest.TestCase):
    def test_none_returns_empty(self):
        self.assertEqual([], _normalize_email_list(None))

    def test_empty_returns_empty(self):
        self.assertEqual([], _normalize_email_list([]))

    def test_list_of_strings(self):
        self.assertEqual(["a@x", "b@x"], _normalize_email_list(["a@x", "b@x"]))

    def test_list_of_dicts(self):
        self.assertEqual(["a@x"], _normalize_email_list([{"value": "a@x"}]))

    def test_scalar(self):
        self.assertEqual(["a@x"], _normalize_email_list("a@x"))


class NeedsUpdate(unittest.TestCase):
    def _existing(self, given="First", family="Last", emails=("a@x",)):
        return {
            "name": {"givenName": given, "familyName": family},
            "emails": list(emails),
        }

    def test_no_changes(self):
        needs, uf, ul, ue = _needs_update(self._existing(), "First", "Last", ["a@x"])
        self.assertFalse(needs)
        self.assertIsNone(uf)
        self.assertIsNone(ul)
        self.assertIsNone(ue)

    def test_first_name_change(self):
        needs, uf, _ul, _ue = _needs_update(self._existing(), "New", "Last", ["a@x"])
        self.assertTrue(needs)
        self.assertEqual("New", uf)

    def test_last_name_change(self):
        needs, _uf, ul, _ue = _needs_update(self._existing(), "First", "New", ["a@x"])
        self.assertTrue(needs)
        self.assertEqual("New", ul)

    def test_email_change(self):
        needs, _uf, _ul, ue = _needs_update(self._existing(), "First", "Last", ["new@x"])
        self.assertTrue(needs)
        self.assertEqual(["new@x"], ue)

    def test_none_or_empty_not_updated(self):
        needs, uf, ul, ue = _needs_update(self._existing(), None, None, [])
        self.assertFalse(needs)
        self.assertIsNone(uf)
        self.assertIsNone(ul)
        self.assertIsNone(ue)


class ProcessCreateAccount(unittest.TestCase):
    @patch(f"{MODULE}.extract_entitlements")
    @patch(f"{MODULE}.create_user")
    @patch(f"{MODULE}.get_user")
    def test_creates_when_missing(self, mock_get, mock_create, mock_extract):
        mock_get.return_value = None
        mock_create.return_value = {"id": "cuid-1"}
        mock_extract.return_value = ["ent:1"]

        result = _process_create_account(
            MagicMock(), "cuid-1", "First", "Last", ["a@x"], True
        )

        self.assertEqual({"cuid": "cuid-1", "entitlements": ["ent:1"]}, result)
        mock_create.assert_called_once()

    @patch(f"{MODULE}.extract_entitlements")
    @patch(f"{MODULE}.update_user")
    @patch(f"{MODULE}.get_user")
    def test_updates_when_changed(self, mock_get, mock_update, mock_extract):
        mock_get.return_value = {
            "name": {"givenName": "Old", "familyName": "Last"},
            "emails": ["a@x"],
        }
        mock_update.return_value = {"id": "cuid-1"}
        mock_extract.return_value = []

        _process_create_account(MagicMock(), "cuid-1", "New", "Last", ["a@x"], True)

        mock_update.assert_called_once()

    @patch(f"{MODULE}.extract_entitlements")
    @patch(f"{MODULE}.update_user")
    @patch(f"{MODULE}.get_user")
    def test_no_update_and_entitlements_disabled(
        self, mock_get, mock_update, mock_extract
    ):
        mock_get.return_value = {
            "name": {"givenName": "First", "familyName": "Last"},
            "emails": ["a@x"],
        }

        result = _process_create_account(
            MagicMock(), "cuid-1", "First", "Last", ["a@x"], False
        )

        mock_update.assert_not_called()
        mock_extract.assert_not_called()
        self.assertEqual([], result["entitlements"])


class CreateGroveAccountInit(unittest.TestCase):
    def test_empty_config_raises(self):
        with self.assertRaises(ConfigError):
            CreateGroveAccount([], "", "")

    def test_missing_required_field_raises(self):
        entry = _entry()
        del entry["grove_api_url"]
        with self.assertRaises(ConfigError):
            CreateGroveAccount([entry], "", "")


class CreateGroveAccountProcess(unittest.TestCase):
    def test_skip_passes_through(self):
        plugin = _build_plugin([_entry(skip=True)])
        data = _data(_full_attrs())

        _context_out, data_out = plugin.process(_context(), data)

        self.assertIs(data, data_out)

    def test_no_fallback_raises_config_error(self):
        plugin = _build_plugin([_entry(requester=SP)])
        data = _data(_full_attrs())

        with self.assertRaises(ResolveConfigError):
            plugin.process(_context(), data)

    def test_missing_attrs_passes_through(self):
        plugin = _build_plugin([_entry()])
        data = _data({"cuid": ["c"]})

        _context_out, data_out = plugin.process(_context(), data)

        self.assertIs(data, data_out)

    def test_missing_attrs_with_error_redirects(self):
        plugin = _build_plugin([_entry(error_on_missing_attrs=True)])
        data = _data({"cuid": ["c"]})

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(ERROR_URL, result.message)

    @patch(f"{MODULE}.create_http_client")
    @patch(f"{MODULE}._process_create_account")
    def test_success_sets_entitlements(self, mock_process, _mock_client):
        mock_process.return_value = {"cuid": "cuid-1", "entitlements": ["ent:1"]}
        plugin = _build_plugin([_entry()])
        data = _data(_full_attrs())

        plugin.process(_context(), data)

        self.assertEqual(["ent:1"], data.attributes["entitlements"])

    @patch(f"{MODULE}.create_http_client")
    @patch(f"{MODULE}._process_create_account")
    def test_success_without_entitlements(self, mock_process, _mock_client):
        mock_process.return_value = {"cuid": "cuid-1", "entitlements": []}
        plugin = _build_plugin([_entry()])
        data = _data(_full_attrs())

        plugin.process(_context(), data)

        self.assertNotIn("entitlements", data.attributes)

    @patch(f"{MODULE}.create_http_client")
    @patch(f"{MODULE}._process_create_account")
    def test_scim_error_redirects(self, mock_process, _mock_client):
        mock_process.side_effect = SCIMError("boom")
        plugin = _build_plugin([_entry()])
        data = _data(_full_attrs())

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(ERROR_URL, result.message)

    @patch(f"{MODULE}.create_http_client")
    @patch(f"{MODULE}._process_create_account")
    def test_error_redirects(self, mock_process, _mock_client):
        mock_process.side_effect = Error("boom")
        plugin = _build_plugin([_entry()])
        data = _data(_full_attrs())

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(ERROR_URL, result.message)


if __name__ == "__main__":
    unittest.main()
