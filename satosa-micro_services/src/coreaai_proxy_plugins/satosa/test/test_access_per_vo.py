import base64
import json
import unittest
from urllib.parse import urlparse

from pytest import raises

from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.access_per_vo import AccessPerVOError
from coreaai_proxy_plugins.satosa.micro_services.access_per_vo import ServiceAccessPerVO


class TestServiceAccessPerVOError(unittest.TestCase):
    def test_duplicate_vo_req_in_configuration_because_auth(self):
        config = {
            "error_url": "https://example.org/error",
            "entitlements_attribute": "epe",
            "service_access_requirements": {
                "sp": [
                  "urn:ns:example2.org:group:vo-a",
                  "urn:ns:example2.org:group:vo-b",
                  "urn:ns:example2.org:group:vo-b#auth",
                ],
            },
        }

        with raises(AccessPerVOError):
            ServiceAccessPerVO(config, "name", "url")

    def test_duplicate_vo_req_in_configuration_because_different_auth(self):
        config = {
            "error_url": "https://example.org/error",
            "entitlements_attribute": "epe",
            "service_access_requirements": {
                "sp": [
                  "urn:ns:example2.org:group:vo-a",
                  "urn:ns:example2.org:group:vo-w-groups:group1#auth1",
                  "urn:ns:example2.org:group:vo-w-groups:group1#auth2",
                ],
            },
        }

        with raises(AccessPerVOError):
            ServiceAccessPerVO(config, "name", "url")


class TestServiceAccessPerVO(unittest.TestCase):
    def setUp(self):
        config = {
            "error_url": "https://example.org/error",
            "registrar_url_base": "https://example.org/fed/registrar/",
            "entitlements_attribute": "epe",
            "filter_entitlements": False,
            "service_access_requirements_skiplist": [
                "sp-skip",
            ],
            "service_access_requirements": {
                "sp-x": [
                  "urn:ns:example.org:group:vo-x",
                  "urn:ns:example.org:group:vo-w-groups:c:d",
                  "urn:ns:example2.org:group:vo-l",
                  "urn:ns:example3.org:example4:group:vo-l",
                  "urn:ns:example3.org:example4:example5:group:vo-l",
                ],
                "sp-y": [
                  "urn:ns:example.org:group:vo-x",
                  "urn:ns:example.org:group:vo-y",
                  "urn:ns:example2.org:group:vo-l",
                  "urn:ns:example3.org:example4:group:vo-l",
                  "urn:ns:example3.org:example4:example5:group:vo-l",
                ],
                "sp-z": [
                  "urn:ns:example.org:group:vo-y",
                ],
                "sp-subgroup": [
                  "urn:ns:example.org:group:vo-w-groups:a:b",
                ],
            },
            "error_per_service": {
                "sp-x": {
                    "message": "SP-X error message",
                    "with_groups": True,
                },
                "sp-z": {
                    "message": "SP-Z error message",
                    "with_groups": False,
                },
                "sp-l": {
                    "message": None,
                    "with_groups": False,
                },
            },
        }

        plugin = ServiceAccessPerVO(config, "name", "url")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        data = InternalData(
            auth_info=AuthenticationInformation(issuer="entity-id-of-issuer"),
            attributes={"epe": ["urn:ns:example.org:group:example#example.org"]},
        )

        data.metadata = {
            "sp-x": {
                "display_name": "Service SP-X",
            },
            "sp-z": {
                "display_name": "Service SP-Z",
            },
        }

        self.context = context
        self.data = data
        self.plugin = plugin

    def test_check_sp_skipped(self):
        self.data.requester = "sp-skip"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-x:subgroup1#pass-sp-is-skipped",
            "urn:ns:example.org:group:vo-y#pass-sp-is-skipped",
        ]
        expected = {
            "urn:ns:example.org:group:vo-x:subgroup1#pass-sp-is-skipped",
            "urn:ns:example.org:group:vo-y#pass-sp-is-skipped",
        }
        new_context, new_data = self.plugin.process(self.context, self.data)
        self.assertEqual(
            expected, set(new_data.attributes[self.plugin.entitlements_attribute])
        )

    def test_check_sp_configured_for_vo(self):
        self.data.requester = "sp-y"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-x:subgroup1#pass-configured-vo",
            "urn:ns:example.org:group:vo-y#pass-configured-vo",
            "urn:ns:example2.org:group:vo-y#fail-no-config",
            "urn:ns:example2.org:group:vo-l#pass-configured-vo",
            "urn:ns:example3.org:group:vo-l#fail-no-config",
            "urn:ns:example3.org:example4:group:vo-l#pass-configured-vo",
            "urn:ns:example3.org:example4:example5:group:vo-l#pass-configured-vo",
        ]
        expected = {
            "urn:ns:example.org:group:vo-x:subgroup1#pass-configured-vo",
            "urn:ns:example.org:group:vo-y#pass-configured-vo",
            "urn:ns:example2.org:group:vo-l#pass-configured-vo",
            "urn:ns:example3.org:example4:group:vo-l#pass-configured-vo",
            "urn:ns:example3.org:example4:example5:group:vo-l#pass-configured-vo",
            # -- would have been filtered
            "urn:ns:example2.org:group:vo-y#fail-no-config",
            "urn:ns:example3.org:group:vo-l#fail-no-config",
        }
        new_context, new_data = self.plugin.process(self.context, self.data)
        self.assertEqual(
            expected, set(new_data.attributes[self.plugin.entitlements_attribute])
        )

    def test_check_sp_configured_for_vo_group(self):
        self.data.requester = "sp-subgroup"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-w-groups:a:b#pass-configured-vo-group",
            "urn:ns:example.org:group:vo-w-groups:c#fail-configured-no-access",
            "urn:ns:example.org:group:vo-x:sub-vo-x#fail-no-config",
            "urn:ns:example.org:group:vo-y#fail-config-no-access",
            "urn:ns:example2.org:group:vo-y#fail-no-config",
            "urn:ns:example2.org:group:vo-l#fail-config-no-access",
            "urn:ns:example3.org:group:vo-l#fail-no-config",
            "urn:ns:example3.org:example4:group:vo-l#fail-config-no-access",
            "urn:ns:example3.org:example4:example5:group:vo-l#fail-config-no-access",
        ]
        expected = {
            "urn:ns:example.org:group:vo-w-groups:a:b#pass-configured-vo-group",
            # -- would have been filtered
            "urn:ns:example.org:group:vo-w-groups:c#fail-configured-no-access",
            "urn:ns:example.org:group:vo-x:sub-vo-x#fail-no-config",
            "urn:ns:example.org:group:vo-y#fail-config-no-access",
            "urn:ns:example2.org:group:vo-y#fail-no-config",
            "urn:ns:example2.org:group:vo-l#fail-config-no-access",
            "urn:ns:example3.org:group:vo-l#fail-no-config",
            "urn:ns:example3.org:example4:group:vo-l#fail-config-no-access",
            "urn:ns:example3.org:example4:example5:group:vo-l#fail-config-no-access",
        }
        new_context, new_data = self.plugin.process(self.context, self.data)
        self.assertEqual(
            expected, set(new_data.attributes[self.plugin.entitlements_attribute])
        )

    def test_check_sp_configured_for_vo_filtered(self):
        self.plugin.filter_entitlements = True
        self.data.requester = "sp-y"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-x:subgroup1#pass-configured-vo",
            "urn:ns:example.org:group:vo-y#pass-configured-vo",
            "urn:ns:example2.org:group:vo-y#fail-no-config",
            "urn:ns:example2.org:group:vo-l#pass-configured-vo",
            "urn:ns:example3.org:group:vo-l#fail-no-config",
            "urn:ns:example3.org:example4:group:vo-l#pass-configured-vo",
            "urn:ns:example3.org:example4:example5:group:vo-l#pass-configured-vo",
        ]
        expected = {
            "urn:ns:example.org:group:vo-x:subgroup1#pass-configured-vo",
            "urn:ns:example.org:group:vo-y#pass-configured-vo",
            "urn:ns:example2.org:group:vo-l#pass-configured-vo",
            "urn:ns:example3.org:example4:group:vo-l#pass-configured-vo",
            "urn:ns:example3.org:example4:example5:group:vo-l#pass-configured-vo",
        }
        new_context, new_data = self.plugin.process(self.context, self.data)
        self.assertEqual(
            expected, set(new_data.attributes[self.plugin.entitlements_attribute])
        )

    def test_check_sp_configured_for_vo_group_filtered(self):
        self.plugin.filter_entitlements = True
        self.data.requester = "sp-subgroup"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-w-groups:a:b#pass-configured-vo-group",
            "urn:ns:example.org:group:vo-w-groups:c#fail-configured-no-access",
            "urn:ns:example.org:group:vo-x:sub-vo-x#fail-no-config",
            "urn:ns:example.org:group:vo-y#fail-config-no-access",
            "urn:ns:example2.org:group:vo-y#fail-no-config",
            "urn:ns:example2.org:group:vo-l#fail-config-no-access",
            "urn:ns:example3.org:group:vo-l#fail-no-config",
            "urn:ns:example3.org:example4:group:vo-l#fail-config-no-access",
            "urn:ns:example3.org:example4:example5:group:vo-l#fail-config-no-access",
        ]
        expected = {
            "urn:ns:example.org:group:vo-w-groups:a:b#pass-configured-vo-group",
        }
        new_context, new_data = self.plugin.process(self.context, self.data)
        self.assertEqual(
            expected, set(new_data.attributes[self.plugin.entitlements_attribute])
        )

    def test_check_vo_with_no_access_anywhere(self):
        self.data.requester = "sp-y"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-e#fail-configured-with-no-access",
            "urn:ns:example.org:group:vo-w-groups:c#fail-configured-with-no-access",
        ]
        expected = self.plugin.error_url
        response = self.plugin.process(self.context, self.data)
        assert response.message.startswith(expected)

    def test_check_sp_not_configured(self):
        self.data.requester = "sp-non-configured"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-x#fail",
            "urn:ns:example.org:group:vo-y#fail",
            "urn:ns:example.org:group:vo-z#fail",
            "urn:ns:example.org:group:vo-w#fail",
        ]
        expected = self.plugin.error_url
        response = self.plugin.process(self.context, self.data)
        assert response.message.startswith(expected)

    def test_check_vo_return_error_urls_with_groups(self):
        self.maxDiff = None

        self.data.requester = "sp-x"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-e#fail-configured-with-no-access",
            "urn:ns:example.org:group:vo-a#fail-configured-with-no-access",
        ]
        expected = {
            "service": "sp-x",
            "service_name": "Service SP-X",
            "message": "SP-X error message",
            "groups": [
                {
                    "req_urn": "urn:ns:example.org:group:vo-x",
                    "req_vo_name": "vo-x",
                    "req_vo_groups": [],
                    "redirect_url": "https://example.org/fed/registrar/?vo=vo-x"
                },
                {
                    "req_urn": "urn:ns:example.org:group:vo-w-groups:c:d",
                    "req_vo_name": "vo-w-groups",
                    "req_vo_groups": ["c", "d"],
                    "redirect_url": "https://example.org/fed/registrar/?vo=vo-w-groups&group=c:d"
                },
                {
                    "req_urn": "urn:ns:example2.org:group:vo-l",
                    "req_vo_name": "vo-l",
                    "req_vo_groups": [],
                    "redirect_url": "https://example.org/fed/registrar/?vo=vo-l"
                },
                {
                    "req_urn": "urn:ns:example3.org:example4:group:vo-l",
                    "req_vo_name": "vo-l",
                    "req_vo_groups": [],
                    "redirect_url": "https://example.org/fed/registrar/?vo=vo-l"
                },
                {
                    "req_urn": "urn:ns:example3.org:example4:example5:group:vo-l",
                    "req_vo_name": "vo-l",
                    "req_vo_groups": [],
                    "redirect_url": "https://example.org/fed/registrar/?vo=vo-l"
                },
            ]
        }
        response = self.plugin.process(self.context, self.data)
        path = urlparse(response.message).path.split("/")[-1]
        payload = base64.urlsafe_b64decode(path)
        payload_decoded = payload.decode("utf-8")
        received_data = json.loads(payload_decoded)
        self.assertDictEqual(expected, received_data)

    def test_check_sp_no_groups_default_error(self):
        self.data.requester = "sp-l"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-e#fail-wrong-entitlements",
        ]
        response = self.plugin.process(self.context, self.data)
        expected = self.plugin.error_url
        assert response.message.startswith(expected)

    def test_check_sp_no_groups_with_message(self):
        self.data.requester = "sp-z"
        self.data.attributes[self.plugin.entitlements_attribute] = [
            "urn:ns:example.org:group:vo-e#fail-wrong-entitlements",
        ]
        error_url = self.plugin.error_url
        expected = {
            "service": "sp-z",
            "service_name": "Service SP-Z",
            "message": "SP-Z error message",
            "groups": []
        }
        response = self.plugin.process(self.context, self.data)
        path = urlparse(response.message).path.split("/")[-1]
        payload = base64.urlsafe_b64decode(path)
        payload_decoded = payload.decode("utf-8")
        received_data = json.loads(payload_decoded)
        self.assertDictEqual(expected, received_data)


if __name__ == "__main__":
    unittest.main()
