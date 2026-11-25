import unittest

from saml2.attribute_converter import ac_factory

from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.attribute_checker import CheckerAttributes
from coreaai_proxy_plugins.satosa.micro_services.attribute_checker import CheckerError


STATE_KEY_MISSING_ATTRS = "missing_attributes"


class AttributeCheckerConfigurationTests(unittest.TestCase):
    def test_empty_config(self):
        config = []
        with self.assertRaises(CheckerError):
            CheckerAttributes(config, "name", "baseUrl")

    def test_missing_required_attributes(self):
        config = [
            {
                "issuer": "https://example.com/idp",
            },
        ]
        with self.assertRaises(CheckerError):
            CheckerAttributes(config, "name", "baseUrl")


class AttributeCheckerDefaultTests(unittest.TestCase):
    def setUp(self):
        context = Context()
        context.state = State()
        self.context = context
        self.internal_data = InternalData(
            requester="a-requester-id",
            auth_info=AuthenticationInformation("", None, "issuer-entity-id"),
        )

        self.config: list[dict[str, str]] = [
            {
                "missing_attributes_state_key": STATE_KEY_MISSING_ATTRS,
                "required_attributes": ["a-required-attribute"],
            },
        ]
        self.plugin = CheckerAttributes(self.config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

    def test_missing_required_attribute(self):
        config = self.config[0]
        ctx, data = self.plugin.process(self.context, self.internal_data)
        missing_attributes = ctx.state.get(STATE_KEY_MISSING_ATTRS)
        self.assertListEqual(missing_attributes, config.get("required_attributes"))

    def test_no_missing_required_attribute(self):
        config = self.config[0]
        self.internal_data.attributes["a-required-attribute"] = ["some-value"]
        ctx, data = self.plugin.process(self.context, self.internal_data)
        missing_attributes = ctx.state.get(STATE_KEY_MISSING_ATTRS)
        self.assertListEqual(missing_attributes, [])

    def test_empty_required_attribute(self):
        config = self.config[0]
        self.internal_data.attributes["a-required-attribute"] = []
        ctx, data = self.plugin.process(self.context, self.internal_data)
        missing_attributes = ctx.state.get(STATE_KEY_MISSING_ATTRS)
        self.assertListEqual(missing_attributes, config["required_attributes"])


if __name__ == "__main__":
    unittest.main()
