import unittest

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State
from satosa.backends.saml2 import SAMLBackend

from coreaai_proxy_plugins.helpers.config import ConfigError
from coreaai_proxy_plugins.satosa.micro_services.ds_url_selector import DiscoURLSelector, Error


SP = "https://sp.example.org"
DISCO = "https://disco.example.org"
DISCO_KEY = SAMLBackend.KEY_SAML_DISCOVERY_SERVICE_URL
# The resolver requires a catch-all (*+*) entry; a skipping fallback makes
# unmatched requesters a no-op.
FALLBACK = {"disco_url": "https://fallback.example.org", "skip": True}


def _plugin(config):
    plugin = DiscoURLSelector(
        config, name="DiscoURLSelector", base_url="https://proxy.example.org"
    )
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context():
    context = Context()
    context.state = State()
    return context


class DiscoURLSelectorConfig(unittest.TestCase):
    def test_empty_config_raises(self):
        with self.assertRaises(Error):
            _plugin([])

    def test_missing_disco_url_raises(self):
        with self.assertRaises(Error):
            _plugin([{"requester": SP}])


class DiscoURLSelectorProcess(unittest.TestCase):
    def setUp(self):
        self.context = _context()

    def _disco(self):
        value = self.context.get_decoration(DISCO_KEY)
        return None if value is None else str(value)

    def test_sets_disco_url_for_matching_requester(self):
        plugin = _plugin([FALLBACK, {"requester": SP, "disco_url": DISCO}])

        plugin.process(self.context, InternalData(requester=SP))

        self.assertEqual(DISCO, self._disco())

    def test_default_entry_applies_to_any_requester(self):
        plugin = _plugin([{"disco_url": DISCO}])

        plugin.process(
            self.context, InternalData(requester="https://anything.example.org")
        )

        self.assertEqual(DISCO, self._disco())

    def test_skip_passes_through(self):
        plugin = _plugin(
            [FALLBACK, {"requester": SP, "disco_url": DISCO, "skip": True}]
        )

        plugin.process(self.context, InternalData(requester=SP))

        self.assertIsNone(self._disco())

    def test_unmatched_requester_falls_back(self):
        plugin = _plugin([FALLBACK, {"requester": SP, "disco_url": DISCO}])

        plugin.process(
            self.context, InternalData(requester="https://other-sp.example.org")
        )

        self.assertIsNone(self._disco())

    def test_config_without_fallback_raises(self):
        plugin = _plugin([{"requester": SP, "disco_url": DISCO}])

        with self.assertRaises(ConfigError):
            plugin.process(self.context, InternalData(requester=SP))


if __name__ == "__main__":
    unittest.main()
