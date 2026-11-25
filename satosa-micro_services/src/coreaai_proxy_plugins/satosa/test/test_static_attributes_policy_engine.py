import unittest

from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.context import Context
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.static_attributes_policy_engine import (
    StaticAttributesPolicyEngine,
)


SP = "https://sp.example.org"
IDP = "https://idp.example.org"


def _plugin(config):
    plugin = StaticAttributesPolicyEngine(config, "", "", "")
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context(requester=SP):
    context = Context()
    context.state = State()
    context.state["SATOSA_BASE"] = {"requester": requester}
    return context


def _data(attributes, issuer=IDP):
    data = InternalData()
    data.auth_info = AuthenticationInformation("", None, issuer)
    data.attributes = attributes
    return data


class StaticAttributesPolicyEngineAppend(unittest.TestCase):
    def setUp(self):
        self.context = _context()

    def test_injects_attribute_when_absent(self):
        plugin = _plugin({"default": {"static_attributes": {"a": ["v1"]}}})
        data = _data({})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": ["v1"]}, data.attributes)

    def test_appends_to_existing_list(self):
        plugin = _plugin({"default": {"static_attributes": {"a": ["v1"]}}})
        data = _data({"a": ["existing"]})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": ["existing", "v1"]}, data.attributes)

    def test_extends_with_list_value(self):
        plugin = _plugin({"default": {"static_attributes": {"a": ["v1", "v2"]}}})
        data = _data({})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": ["v1", "v2"]}, data.attributes)

    def test_appends_string_value(self):
        plugin = _plugin({"default": {"static_attributes": {"a": "v1"}}})
        data = _data({})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": ["v1"]}, data.attributes)

    def test_string_valued_existing_attribute_is_replaced(self):
        # Legacy handling: when the incoming attribute value is a string
        # (not a list), it is replaced with the first configured value.
        plugin = _plugin({"default": {"static_attributes": {"a": ["new"]}}})
        data = _data({"a": "old"})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": "new"}, data.attributes)


class StaticAttributesPolicyEngineOverwrite(unittest.TestCase):
    def setUp(self):
        self.context = _context()

    def test_overwrite_replaces_existing_values(self):
        plugin = _plugin(
            {"default": {"policy": "OVERWRITE", "static_attributes": {"a": ["new"]}}}
        )
        data = _data({"a": ["old"]})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": ["new"]}, data.attributes)


class StaticAttributesPolicyEngineDoNotChangeIfExists(unittest.TestCase):
    def setUp(self):
        self.context = _context()

    def test_keeps_existing_value(self):
        plugin = _plugin(
            {
                "default": {
                    "policy": "DO_NOT_CHANGE_IF_EXISTS",
                    "static_attributes": {"a": ["new"]},
                }
            }
        )
        data = _data({"a": ["old"]})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": ["old"]}, data.attributes)

    def test_injects_when_absent(self):
        plugin = _plugin(
            {
                "default": {
                    "policy": "DO_NOT_CHANGE_IF_EXISTS",
                    "static_attributes": {"a": ["new"]},
                }
            }
        )
        data = _data({})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": ["new"]}, data.attributes)

    def test_keeps_existing_but_still_adds_absent_attributes(self):
        plugin = _plugin(
            {
                "default": {
                    "policy": "DO_NOT_CHANGE_IF_EXISTS",
                    "static_attributes": {"a": ["new_a"], "b": ["new_b"]},
                }
            }
        )
        data = _data({"a": ["old_a"]})

        plugin.process(self.context, data)

        self.assertDictEqual({"a": ["old_a"], "b": ["new_b"]}, data.attributes)


class StaticAttributesPolicyEngineResolution(unittest.TestCase):
    def test_per_sp_config_overrides_default(self):
        plugin = _plugin(
            {
                "default": {"static_attributes": {"a": ["from-default"]}},
                SP: {"static_attributes": {"a": ["from-sp"]}},
            }
        )
        data = _data({})

        plugin.process(_context(requester=SP), data)

        self.assertDictEqual({"a": ["from-sp"]}, data.attributes)

    def test_per_idp_config_used_when_no_sp_match(self):
        plugin = _plugin(
            {
                "default": {"static_attributes": {"a": ["from-default"]}},
                IDP: {"static_attributes": {"a": ["from-idp"]}},
            }
        )
        data = _data({}, issuer=IDP)

        # requester (SP) is not a key in the config, so the per-IdP entry applies
        plugin.process(_context(requester="https://other-sp.example.org"), data)

        self.assertDictEqual({"a": ["from-idp"]}, data.attributes)


class StaticAttributesPolicyEngineConfigHandling(unittest.TestCase):
    def test_empty_string_key_aliases_default(self):
        plugin = _plugin({"": {"static_attributes": {"a": ["v1"]}}})
        data = _data({})

        plugin.process(_context(), data)

        self.assertDictEqual({"a": ["v1"]}, data.attributes)

    def test_both_default_and_empty_key_is_noop(self):
        plugin = _plugin(
            {
                "default": {"static_attributes": {"a": ["v1"]}},
                "": {"static_attributes": {"a": ["v2"]}},
            }
        )
        data = _data({"keep": ["me"]})

        plugin.process(_context(), data)

        self.assertDictEqual({"keep": ["me"]}, data.attributes)

    def test_no_default_config_is_noop(self):
        plugin = _plugin({})
        data = _data({"a": ["x"]})

        plugin.process(_context(), data)

        self.assertDictEqual({"a": ["x"]}, data.attributes)

    def test_empty_config_entry_is_noop(self):
        plugin = _plugin({"default": []})
        data = _data({"a": ["x"]})

        plugin.process(_context(), data)

        self.assertDictEqual({"a": ["x"]}, data.attributes)

    def test_missing_requester_is_noop(self):
        plugin = _plugin({"default": {"static_attributes": {"a": ["v1"]}}})
        data = _data({"a": ["x"]})
        context = Context()
        context.state = State()  # no SATOSA_BASE entry

        plugin.process(context, data)

        self.assertDictEqual({"a": ["x"]}, data.attributes)


if __name__ == "__main__":
    unittest.main()
