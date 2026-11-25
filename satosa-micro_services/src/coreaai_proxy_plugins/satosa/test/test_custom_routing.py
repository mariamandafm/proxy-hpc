import unittest

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.custom_routing import (
    DecideBackendByRequester,
    CustomRoutingError,
)


SP_X = "https://sp-x.example.org"
BE1 = "backend-1"
FALLBACK = "backend-fallback"


def _plugin(config):
    plugin = DecideBackendByRequester(config, "", "")
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context():
    context = Context()
    context.state = State()
    return context


class DecideBackendByRequesterConfig(unittest.TestCase):
    def test_missing_backend_by_requester_raises(self):
        with self.assertRaises(CustomRoutingError):
            _plugin({})

    def test_no_fallback_raises(self):
        with self.assertRaises(CustomRoutingError):
            _plugin({"backend_by_requester": {SP_X: BE1}})

    def test_non_string_values_raise(self):
        with self.assertRaises(CustomRoutingError):
            _plugin({"backend_by_requester": {SP_X: 123, "default": FALLBACK}})


class DecideBackendByRequesterProcess(unittest.TestCase):
    def setUp(self):
        self.context = _context()

    def test_routes_known_requester(self):
        plugin = _plugin({"backend_by_requester": {SP_X: BE1, "default": FALLBACK}})

        plugin.process(self.context, InternalData(requester=SP_X))

        self.assertEqual(BE1, self.context.target_backend)

    def test_unknown_requester_uses_default_fallback(self):
        plugin = _plugin({"backend_by_requester": {SP_X: BE1, "default": FALLBACK}})

        plugin.process(
            self.context, InternalData(requester="https://other.example.org")
        )

        self.assertEqual(FALLBACK, self.context.target_backend)

    def test_empty_string_key_acts_as_fallback(self):
        plugin = _plugin({"backend_by_requester": {SP_X: BE1, "": FALLBACK}})

        plugin.process(
            self.context, InternalData(requester="https://other.example.org")
        )

        self.assertEqual(FALLBACK, self.context.target_backend)


if __name__ == "__main__":
    unittest.main()
