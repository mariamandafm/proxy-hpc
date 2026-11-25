import unittest

from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.context import Context
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.aarc_group_role_processor import (
    AarcGroupRoleProcessor,
)


URN_NAMESPACE = "urn:geant:example.org"


def _config(**overrides):
    """Build a config that resolves (via default/default) regardless of issuer/requester."""
    settings = {
        "urn_namespace": URN_NAMESPACE,
        "from_group_role_attribute": "groups",
        "to_group_role_attribute": "eduperson_entitlement",
    }
    settings.update(overrides)
    return {"default": {"default": settings}}


def _plugin(config):
    plugin = AarcGroupRoleProcessor(config, "", "")
    plugin.next = lambda context, data: (context, data)
    return plugin


def _internal_data(
    attributes,
    requester="https://sp.example.org",
    issuer="https://idp.example.org",
):
    data = InternalData()
    data.auth_info = AuthenticationInformation("", None, issuer)
    data.requester = requester
    data.attributes = attributes
    return data


class AarcGroupRoleProcessorEncoding(unittest.TestCase):
    def setUp(self):
        self.context = Context()
        self.context.state = State()

    def test_encodes_groups_as_aarc_entitlements_and_clears_source(self):
        plugin = _plugin(_config())
        data = _internal_data({"groups": ["admins", "users"]})

        plugin.process(self.context, data)

        self.assertDictEqual(
            {
                "eduperson_entitlement": [
                    f"{URN_NAMESPACE}:group:admins",
                    f"{URN_NAMESPACE}:group:users",
                ]
            },
            data.attributes,
        )

    def test_appends_attribute_authority_when_configured(self):
        plugin = _plugin(_config(attribute_authority="aa.example.org"))
        data = _internal_data({"groups": ["admins"]})

        plugin.process(self.context, data)

        self.assertEqual(
            [f"{URN_NAMESPACE}:group:admins#aa.example.org"],
            data.attributes["eduperson_entitlement"],
        )

    def test_quotes_special_characters_keeping_slash_and_colon(self):
        plugin = _plugin(_config())
        data = _internal_data({"groups": ["dept name/sub:role"]})

        plugin.process(self.context, data)

        # space is percent-encoded; "/" and ":" are preserved (safe="/:")
        self.assertEqual(
            [f"{URN_NAMESPACE}:group:dept%20name/sub:role"],
            data.attributes["eduperson_entitlement"],
        )

    def test_appends_to_existing_target_attribute(self):
        plugin = _plugin(_config())
        data = _internal_data(
            {"groups": ["admins"], "eduperson_entitlement": ["pre-existing"]}
        )

        plugin.process(self.context, data)

        self.assertEqual(
            ["pre-existing", f"{URN_NAMESPACE}:group:admins"],
            data.attributes["eduperson_entitlement"],
        )

    def test_keeps_source_attribute_when_clear_disabled(self):
        plugin = _plugin(_config(clear_from_group_role_attribute=False))
        data = _internal_data({"groups": ["admins"]})

        plugin.process(self.context, data)

        self.assertDictEqual(
            {
                "groups": ["admins"],
                "eduperson_entitlement": [f"{URN_NAMESPACE}:group:admins"],
            },
            data.attributes,
        )

    def test_no_source_groups_is_noop_passthrough(self):
        plugin = _plugin(_config())
        data = _internal_data({"unrelated": ["value"]})

        plugin.process(self.context, data)

        self.assertDictEqual({"unrelated": ["value"]}, data.attributes)


class AarcGroupRoleProcessorDisabled(unittest.TestCase):
    def setUp(self):
        self.context = Context()
        self.context.state = State()

    def test_disabled_config_passes_through_untouched(self):
        plugin = _plugin({"default": {"default": {"disabled": True}}})
        data = _internal_data({"groups": ["admins"]})

        plugin.process(self.context, data)

        self.assertDictEqual({"groups": ["admins"]}, data.attributes)

    def test_empty_config_passes_through_untouched(self):
        plugin = _plugin({})
        data = _internal_data({"groups": ["admins"]})

        plugin.process(self.context, data)

        self.assertDictEqual({"groups": ["admins"]}, data.attributes)


if __name__ == "__main__":
    unittest.main()
