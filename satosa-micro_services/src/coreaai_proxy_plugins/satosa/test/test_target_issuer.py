import unittest

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.helpers.config import ConfigError
from coreaai_proxy_plugins.satosa.micro_services.target_issuer import TargetIssuer, Error


SP = "https://sp.example.org"
IDP = "https://idp.example.org"

# The resolver requires a catch-all (*+*) entry; a skipping fallback makes
# unmatched requesters a no-op.
FALLBACK = {"target_issuer": "https://fallback.example.org", "skip": True}


def _plugin(config):
    plugin = TargetIssuer(
        config, name="TargetIssuer", base_url="https://proxy.example.org"
    )
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context():
    context = Context()
    context.state = State()
    return context


class TargetIssuerConfig(unittest.TestCase):
    def test_empty_config_raises(self):
        with self.assertRaises(Error):
            _plugin([])

    def test_missing_target_issuer_raises(self):
        with self.assertRaises(Error):
            _plugin([{"requester": SP}])


class TargetIssuerProcess(unittest.TestCase):
    def setUp(self):
        self.context = _context()

    def test_sets_target_entityid_for_matching_requester(self):
        plugin = _plugin([FALLBACK, {"requester": SP, "target_issuer": IDP}])
        data = InternalData(requester=SP)

        plugin.process(self.context, data)

        self.assertEqual(
            IDP, self.context.get_decoration(Context.KEY_TARGET_ENTITYID)
        )

    def test_default_entry_applies_to_any_requester(self):
        plugin = _plugin([{"target_issuer": IDP}])
        data = InternalData(requester="https://anything.example.org")

        plugin.process(self.context, data)

        self.assertEqual(
            IDP, self.context.get_decoration(Context.KEY_TARGET_ENTITYID)
        )

    def test_skip_passes_through(self):
        plugin = _plugin(
            [FALLBACK, {"requester": SP, "target_issuer": IDP, "skip": True}]
        )
        data = InternalData(requester=SP)

        plugin.process(self.context, data)

        self.assertIsNone(
            self.context.get_decoration(Context.KEY_TARGET_ENTITYID)
        )

    def test_unmatched_requester_falls_back(self):
        plugin = _plugin([FALLBACK, {"requester": SP, "target_issuer": IDP}])
        data = InternalData(requester="https://other-sp.example.org")

        plugin.process(self.context, data)

        # falls back to the skipping default -> no decoration
        self.assertIsNone(
            self.context.get_decoration(Context.KEY_TARGET_ENTITYID)
        )

    def test_config_without_fallback_raises(self):
        # No catch-all (*+*) entry -> the resolver raises for every request.
        plugin = _plugin([{"requester": SP, "target_issuer": IDP}])
        data = InternalData(requester=SP)

        with self.assertRaises(ConfigError):
            plugin.process(self.context, data)


if __name__ == "__main__":
    unittest.main()
