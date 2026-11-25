import unittest
from unittest.mock import mock_open, patch

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.helpers.config import ConfigError
from coreaai_proxy_plugins.satosa.micro_services.iuids_by_email import IUIDsByEmail, Error
from coreaai_proxy_plugins.satosa.micro_services.iuids_by_email import load_exported_data


SP = "https://sp.example.org"
PATCH_TARGET = "coreaai_proxy_plugins.satosa.micro_services.iuids_by_email.load_exported_data"
EXPORT = {"a@b.org": ["iuid-1", "iuid-2"]}


def _plugin(config):
    plugin = IUIDsByEmail(config, "", "")
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context():
    context = Context()
    context.state = State()
    return context


def _catchall(skip=None):
    entry = {
        "attribute_email": "email",
        "attribute_iuids": "iuids",
        "datafile": "export.json",
    }
    if skip is not None:
        entry["skip"] = skip
    return [entry]


class IUIDsByEmailConfig(unittest.TestCase):
    def test_empty_config_raises(self):
        with self.assertRaises(Error):
            _plugin([])

    def test_missing_required_field_raises(self):
        with self.assertRaises(Error):
            _plugin([{"attribute_email": "email", "attribute_iuids": "iuids"}])


class IUIDsByEmailProcess(unittest.TestCase):
    def setUp(self):
        self.context = _context()

    @patch(PATCH_TARGET, return_value=EXPORT)
    def test_injects_iuids_for_matched_email(self, _mock):
        plugin = _plugin(_catchall())
        data = InternalData(requester=SP, attributes={"email": ["a@b.org"]})

        plugin.process(self.context, data)

        self.assertEqual(["iuid-1", "iuid-2"], data.attributes["iuids"])

    @patch(PATCH_TARGET, return_value=EXPORT)
    def test_merges_with_existing_iuids(self, _mock):
        plugin = _plugin(_catchall())
        data = InternalData(
            requester=SP, attributes={"email": ["a@b.org"], "iuids": ["existing"]}
        )

        plugin.process(self.context, data)

        self.assertEqual(["existing", "iuid-1", "iuid-2"], data.attributes["iuids"])

    @patch(PATCH_TARGET, return_value=EXPORT)
    def test_no_match_keeps_existing_iuids(self, _mock):
        plugin = _plugin(_catchall())
        data = InternalData(
            requester=SP, attributes={"email": ["x@y.org"], "iuids": ["existing"]}
        )

        plugin.process(self.context, data)

        self.assertEqual(["existing"], data.attributes["iuids"])

    @patch(PATCH_TARGET, return_value=EXPORT)
    def test_skip_passes_through(self, _mock):
        plugin = _plugin(_catchall(skip=True))
        data = InternalData(requester=SP, attributes={"email": ["a@b.org"]})

        plugin.process(self.context, data)

        self.assertNotIn("iuids", data.attributes)

    def test_config_without_fallback_raises(self):
        plugin = _plugin(
            [
                {
                    "requester": SP,
                    "attribute_email": "email",
                    "attribute_iuids": "iuids",
                    "datafile": "export.json",
                }
            ]
        )
        data = InternalData(requester=SP, attributes={"email": ["a@b.org"]})

        with self.assertRaises(ConfigError):
            plugin.process(self.context, data)


class IUIDsByEmailLoadExportedData(unittest.TestCase):
    def test_load_exported_data(self):
        m = mock_open(read_data='{"a": 1}')

        with patch("builtins.open", m):
            result = load_exported_data("dummy.json")

        self.assertEqual(result, {"a": 1})
        m.assert_called_once_with("dummy.json")


if __name__ == "__main__":
    unittest.main()
