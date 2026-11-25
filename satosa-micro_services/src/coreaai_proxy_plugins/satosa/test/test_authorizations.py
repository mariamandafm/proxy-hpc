import unittest

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.authorizations import PreserveAuthorizations


STATE_KEY = "authorizations"
FRONTEND = "oidc-frontend"


def _plugin(config=None):
    plugin = PreserveAuthorizations(
        config or {"authorizations_state_key": STATE_KEY}, "", ""
    )
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context(state_data=None, target_frontend=FRONTEND):
    context = Context()
    context.state = State()
    for key, value in (state_data or {}).items():
        context.state[key] = value
    context.target_frontend = target_frontend
    return context


class PreserveAuthorizationsConfig(unittest.TestCase):
    def test_missing_state_key_raises(self):
        with self.assertRaises(KeyError):
            PreserveAuthorizations({}, "", "")


class PreserveAuthorizationsProcess(unittest.TestCase):
    def test_stores_requested_oidc_scopes(self):
        plugin = _plugin()
        context = _context(
            {FRONTEND: {"oidc_request": {"scope": "openid email profile"}}}
        )

        plugin.process(context, InternalData(requester="sp"))

        self.assertEqual(
            ["openid", "email", "profile"], context.state[STATE_KEY]
        )

    def test_no_oidc_request_stores_empty_list(self):
        plugin = _plugin()
        context = _context({FRONTEND: {}})

        plugin.process(context, InternalData(requester="sp"))

        self.assertEqual([], context.state[STATE_KEY])

    def test_no_frontend_state_stores_empty_list(self):
        plugin = _plugin()
        context = _context({})

        plugin.process(context, InternalData(requester="sp"))

        self.assertEqual([], context.state[STATE_KEY])


if __name__ == "__main__":
    unittest.main()
