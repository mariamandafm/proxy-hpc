import unittest


from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.context import Context
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.inject_attributes import InjectAttributes
from coreaai_proxy_plugins.satosa.micro_services.inject_attributes import InjectAttributesError
from coreaai_proxy_plugins.satosa.micro_services.inject_attributes import (
    SUBJECT_ID_ATTRIBUTE,
    EMAIL_ATTRIBUTE,
    EU_LOGIN_DOMAIN_ATTRIBUTE,
)


ENTITY_CATEGORY_SUPPORT_RNS = "http://refeds.org/category/research-and-scholarship"


class InjectAttributes_Config(unittest.TestCase):
    def test_strategy_any_and_empty_search_for(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "test",
                            "values": ["value"],
                            "strategy": "any",
                            "search_for": {},
                        }
                    ],
                }
            }
        }

        with self.assertRaises(InjectAttributesError):
            InjectAttributes(config, "", "")

    def test_strategy_any_and_empty_search_for_but_disabled_is_true(self):
        config = {
            "default": {
                "default": {
                    "disabled": True,
                    "attributes": [
                        {
                            "attribute": "test",
                            "values": ["value"],
                            "strategy": "any",
                            "search_for": {},
                        }
                    ],
                }
            }
        }

        InjectAttributes(config, "", "")

    def test_strategy_any_and_empty_search_for_one_requester_issuer_combination(self):
        config = {
            "default": {"default": {"disabled": True}},
            "issuer": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "test",
                            "values": ["value"],
                            "strategy": "any",
                            "search_for": {},
                        }
                    ],
                }
            },
        }
        with self.assertRaises(InjectAttributesError):
            InjectAttributes(config, "", "")

    def test_no_attributes_and_no_disabled(self):
        config = {"default": {"default": {}}}
        with self.assertRaises(InjectAttributesError):
            InjectAttributes(config, "", "")

    def test_no_attributes_and_disabled_false(self):
        config = {"default": {"default": {"disabled": False}}}
        with self.assertRaises(InjectAttributesError):
            InjectAttributes(config, "", "")

    def test_empty_values_attributes(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "test",
                            "values": [],
                            "strategy": "any",
                            "all_entity_categories_support": ["some_category"],
                        }
                    ],
                }
            }
        }
        with self.assertRaises(InjectAttributesError):
            InjectAttributes(config, "", "")

    def test_disabled_configurations(self):
        config = {"default": {"default": {"disabled": True}}}
        InjectAttributes(config, "", "")


class InjectAttributes_SearchFor_Any(unittest.TestCase):
    def setUp(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "test",
                            "values": ["value"],
                            "strategy": "any",
                            "search_for": {
                                "all_entity_categories_support": [
                                    ENTITY_CATEGORY_SUPPORT_RNS
                                ],
                                "any_attributes": ["special"],
                            },
                        }
                    ]
                }
            }
        }
        plugin = InjectAttributes(config, "", "")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_idp_without_category_and_no_special_attr__must_not_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITHOUT_RNS")
        internal_data.requester = "requester"
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual({"foo": ["bar"]}, internal_data.attributes)

    def test_idp_with_category_and_no_special_attr__must_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.requester = "requester"
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"foo": ["bar"], "test": ["value"]}, internal_data.attributes
        )

    def test_idp_without_category_and_special_attribute__must_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITHOUT_RNS")
        internal_data.requester = "requester"
        internal_data.attributes = {"special": ["value"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"special": ["value"], "test": ["value"]}, internal_data.attributes
        )

    def test_idp_with_category_and_special_attribute__must_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.requester = "requester"
        internal_data.attributes = {"special": ["value"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"special": ["value"], "test": ["value"]}, internal_data.attributes
        )


class InjectAttributes_SearchFor_All(unittest.TestCase):
    def setUp(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "test",
                            "values": ["value"],
                            "strategy": "all",
                            "search_for": {
                                "all_entity_categories_support": [
                                    ENTITY_CATEGORY_SUPPORT_RNS
                                ],
                                "any_attributes": ["special"],
                                "all_assurance_certifications": [
                                    "https://refeds.org/sirtfi"
                                ],
                            },
                        },
                        {
                            "attribute": "test_overwrite",
                            "values": ["value"],
                            "overwrite_values": True,
                            "strategy": "all",
                            "search_for": {
                                "all_entity_categories_support": [
                                    ENTITY_CATEGORY_SUPPORT_RNS
                                ],
                                "any_attributes": ["special_for_test_overwrite"],
                                "all_assurance_certifications": [
                                    "https://refeds.org/sirtfi",
                                ],
                            },
                        },
                    ]
                }
            }
        }
        plugin = InjectAttributes(config, "", "")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_idp_without_category_and_no_special_attr__must_not_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITHOUT_RNS")
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual({"foo": ["bar"]}, internal_data.attributes)

    def test_idp_with_category_and_no_special_attr__must_not_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual({"foo": ["bar"]}, internal_data.attributes)

    def test_idp_without_category_and_special_attribute__must_not_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITHOUT_RNS")
        internal_data.attributes = {"special": ["value"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual({"special": ["value"]}, internal_data.attributes)

    def test_idp_with_category_and_special_attribute__must_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.attributes = {"special": ["value"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS],
                "assurance_certifications": ["https://refeds.org/sirtfi"],
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"special": ["value"], "test": ["value"]}, internal_data.attributes
        )

    def test_idp_with_category_and_special_attribute__must_inject_value_to_existing_attribute(
        self,
    ):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.attributes = {"special": ["value"], "test": ["default_value"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS],
                "assurance_certifications": ["https://refeds.org/sirtfi"],
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"special": ["value"], "test": ["default_value", "value"]},
            internal_data.attributes,
        )

    def test_idp_with_overwrite_values(
        self,
    ):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.attributes = {
            "special_for_test_overwrite": ["value"],
            "test_overwrite": ["default_value"],
        }
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS],
                "assurance_certifications": ["https://refeds.org/sirtfi"],
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"special_for_test_overwrite": ["value"], "test_overwrite": ["value"]},
            internal_data.attributes,
        )


class InjectAttributes_StrategyAlways(unittest.TestCase):
    def setUp(self):
        config = {
            "default": {"default": {"disabled": True}},
            "IDP_WITH_RNS": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "test",
                            "values": ["value"],
                            "strategy": "always",
                            "search_for": {},
                        }
                    ]
                }
            },
        }

        plugin = InjectAttributes(config, "", "")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_idp_not_strategy_any_must_not_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITHOUT_RNS")
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual({"foo": ["bar"]}, internal_data.attributes)

    def test_idp_strategy_any_must_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"foo": ["bar"], "test": ["value"]}, internal_data.attributes
        )


class InjectAttributes_MultipleAttrbutes(unittest.TestCase):
    def setUp(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "test01",
                            "values": ["value"],
                            "strategy": "any",
                            "search_for": {
                                "all_entity_categories_support": [
                                    ENTITY_CATEGORY_SUPPORT_RNS
                                ],
                                "any_attributes": ["special"],
                                "all_assurance_certifications": [
                                    "https://refeds.org/sirtfi"
                                ],
                            },
                        },
                        {
                            "attribute": "test02",
                            "values": ["value01", "value02"],
                            "strategy": "all",
                            "search_for": {
                                "all_entity_categories_support": [
                                    ENTITY_CATEGORY_SUPPORT_RNS
                                ],
                            },
                        },
                        {
                            "attribute": "test02",
                            "values": ["value03", "value04"],
                            "strategy": "all",
                            "search_for": {
                                "all_entity_categories_support": [
                                    ENTITY_CATEGORY_SUPPORT_RNS
                                ],
                                "any_attributes": ["enrichment_test1"],
                            },
                        },
                        {
                            "attribute": "test02",
                            "values": ["value03", "value04"],
                            "overwrite_values": True,
                            "strategy": "all",
                            "search_for": {
                                "all_entity_categories_support": [
                                    ENTITY_CATEGORY_SUPPORT_RNS
                                ],
                                "any_attributes": ["enrichment_test2"],
                            },
                        },
                    ]
                }
            }
        }
        plugin = InjectAttributes(config, "", "")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_rns_idp_inject_multiple_attributes(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"foo": ["bar"], "test01": ["value"], "test02": ["value01", "value02"]},
            internal_data.attributes,
        )

    def test_rns_idp_enrich_attribute_in_separate_steps(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.attributes = {"foo": ["bar"], "enrichment_test1": ["value"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                "foo": ["bar"],
                "enrichment_test1": ["value"],
                "test01": ["value"],
                "test02": ["value01", "value02", "value03", "value04"],
            },
            internal_data.attributes,
        )

    def test_rns_idp_enrich_attribute_in_separate_steps_and_overwrite(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_WITH_RNS")
        internal_data.attributes = {"foo": ["bar"], "enrichment_test2": ["value"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "IDP_WITH_RNS": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS]
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                "foo": ["bar"],
                "enrichment_test2": ["value"],
                "test01": ["value"],
                "test02": ["value03", "value04"],
            },
            internal_data.attributes,
        )


class InjectAttributes_RegistrationAuthority(unittest.TestCase):
    def setUp(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "test",
                            "values": ["value"],
                            "strategy": "all",
                            "search_for": {
                                "all_entity_categories_support": [
                                    ENTITY_CATEGORY_SUPPORT_RNS
                                ],
                                "all_assurance_certifications": [
                                    "https://refeds.org/sirtfi"
                                ],
                                "any_registration_authorities": [
                                    "https://regauth1",
                                    "https://regauth2",
                                ],
                            },
                        },
                    ]
                }
            }
        }

        plugin = InjectAttributes(config, "", "")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_idp_must_not_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "RS_SIRTFI_IDP")
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "RS_SIRTFI_IDP": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS],
                "assurance_certifications": ["https://refeds.org/sirtfi"],
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual({"foo": ["bar"]}, internal_data.attributes)

    def test_idp_must_inject(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "RS_SIRTFI_IDP")
        internal_data.attributes = {"foo": ["bar"]}
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {"supported_entity_categories": []},
            "RS_SIRTFI_IDP": {
                "supported_entity_categories": [ENTITY_CATEGORY_SUPPORT_RNS],
                "assurance_certifications": ["https://refeds.org/sirtfi"],
                "registration_info": {"registration_authority": "https://regauth2"},
            },
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {"foo": ["bar"], "test": ["value"]}, internal_data.attributes
        )


class InjectAttributes_SearchFor_Any_Subject_ID(unittest.TestCase):
    def setUp(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "https://core.aai.geant.org/claims/org_country",
                            "values": ["GRC"],
                            "strategy": "any",
                            "search_for": {
                                "any_subject_id": ["01J5TRS4T0T63F4YXTY3V4NSWA"],
                                "any_attributes": ["special"],
                            },
                        }
                    ]
                }
            }
        }
        plugin = InjectAttributes(config, "", "")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_user_without_subject_id(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {"a-random-attribute": ["abcde"]}

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                "a-random-attribute": ["abcde"],
            },
            internal_data.attributes,
        )

    def test_user_with_matching_subject_id(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {
            SUBJECT_ID_ATTRIBUTE: ["01J5TRS4T0T63F4YXTY3V4NSWA"]
        }

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                SUBJECT_ID_ATTRIBUTE: ["01J5TRS4T0T63F4YXTY3V4NSWA"],
                "https://core.aai.geant.org/claims/org_country": ["GRC"],
            },
            internal_data.attributes,
        )

    def test_user_without_matching_subject_id(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {SUBJECT_ID_ATTRIBUTE: ["abcde"]}

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                SUBJECT_ID_ATTRIBUTE: ["abcde"],
            },
            internal_data.attributes,
        )


class InjectAttributes_SearchFor_Any_Email(unittest.TestCase):
    def setUp(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "https://core.aai.geant.org/claims/org_country",
                            "values": ["GRC"],
                            "strategy": "any",
                            "search_for": {
                                "any_email": ["test@example.com"],
                            },
                        }
                    ]
                }
            }
        }
        plugin = InjectAttributes(config, "", "")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_user_without_email(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {"a-random-attribute": ["abcde"]}

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                "a-random-attribute": ["abcde"],
            },
            internal_data.attributes,
        )

    def test_user_with_matching_email(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {EMAIL_ATTRIBUTE: ["test@example.com"]}

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                EMAIL_ATTRIBUTE: ["test@example.com"],
                "https://core.aai.geant.org/claims/org_country": ["GRC"],
            },
            internal_data.attributes,
        )

    def test_user_without_matching_email(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {EMAIL_ATTRIBUTE: ["test@another.example.com"]}

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                EMAIL_ATTRIBUTE: ["test@another.example.com"],
            },
            internal_data.attributes,
        )


class InjectAttributes_SearchFor_Any_EU_Login_Domain(unittest.TestCase):
    def setUp(self):
        config = {
            "default": {
                "default": {
                    "attributes": [
                        {
                            "attribute": "vpea",
                            "values": ["staff@ec.europa.eu"],
                            "strategy": "any",
                            "search_for": {
                                "any_eu_login_domain": ["eu.europa.ec"],
                            },
                        }
                    ]
                }
            }
        }
        plugin = InjectAttributes(config, "", "")
        plugin.next = lambda context, data: (context, data)  # type: ignore

        context = Context()
        context.state = State()  # type: ignore

        self.context = context
        self.plugin = plugin

    def test_user_without_domain_attribute(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {"a-random-attribute": ["abcde"]}

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                "a-random-attribute": ["abcde"],
            },
            internal_data.attributes,
        )

    def test_user_with_matching_domain_attribute(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {EU_LOGIN_DOMAIN_ATTRIBUTE: ["eu.europa.ec"]}

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                EU_LOGIN_DOMAIN_ATTRIBUTE: ["eu.europa.ec"],
                "vpea": ["staff@ec.europa.eu"],
            },
            internal_data.attributes,
        )

    def test_user_without_matching_domain_attribute(self):
        internal_data = InternalData()
        internal_data.requester = "requester"
        internal_data.attributes = {EU_LOGIN_DOMAIN_ATTRIBUTE: ["something-else"]}

        self.plugin.process(self.context, internal_data)
        self.assertDictEqual(
            {
                EU_LOGIN_DOMAIN_ATTRIBUTE: ["something-else"],
            },
            internal_data.attributes,
        )


if __name__ == "__main__":
    unittest.main()
