import unittest
from pytest import raises
from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.state import State
from coreaai_proxy_plugins.satosa.micro_services.attribute_deriver import AttributeDeriver, Error


class TestConfigError(unittest.TestCase):
    def test_missing_attribute_derivation_strategies(self):
        config = [
            {
                "error_url": "https://example.org/error",
            }
        ]

        with raises(Error):
            AttributeDeriver(
                config, name="AttributeDeriver", base_url="https://proxy.example.org"
            )

    def test_missing_attr_in_strategy_definition(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "foo": [{"strategy": "set"}],
                },
            }
        ]

        with raises(Error):
            AttributeDeriver(
                config, name="AttributeDeriver", base_url="https://proxy.example.org"
            )

    def test_missing_strategy_in_strategy_definition(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "foo": [{"attr_source": "foo"}],
                },
            }
        ]

        with raises(Error):
            AttributeDeriver(
                config, name="AttributeDeriver", base_url="https://proxy.example.org"
            )

    def test_invalid_strategy_name_in_strategy_definition(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "foo": [{"strategy": "invalid_strategy", "attr_source": "foo"}],
                },
            }
        ]

        with raises(Error):
            AttributeDeriver(
                config, name="AttributeDeriver", base_url="https://proxy.example.org"
            )

    def test_missing_index_in_select_strategy_definition(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "foo": [
                        {"attr_source": "givenname", "strategy": "set"},
                        {
                            "attr_source": "displayname",
                            "strategy": "select",
                            "strategy_options": {
                                "strip": [","],
                                "stopwords": [
                                    r"mr\.?",
                                ],
                            },
                        },
                    ],
                },
            }
        ]

        with raises(Error):
            AttributeDeriver(
                config, name="AttributeDeriver", base_url="https://proxy.example.org"
            )

    def test_missing_strategy_options_in_select_strategy_definition(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "foo": [
                        {"attr_source": "givenname", "strategy": "set"},
                        {
                            "attr_source": "displayname",
                            "strategy": "select",
                        },
                    ],
                },
            }
        ]

        with raises(Error):
            AttributeDeriver(
                config, name="AttributeDeriver", base_url="https://proxy.example.org"
            )


class TestGoodConfig(unittest.TestCase):
    def test_missing_strategy_list_in_attribute_derivation_strategies(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {},
            }
        ]

        plugin = AttributeDeriver(
            config,
            name="AttributeDeriver",
            base_url="https://proxy.example.org",
        )

        plugin.next = lambda context, data: (context, data)
        context = Context()
        context.state = State()

        initial_internal_attributes = {
            "username": ["displayname_value"],
        }

        expected_internal_attributes = {
            "username": ["displayname_value"],
        }

        data = InternalData(
            auth_info=AuthenticationInformation(issuer="entity-id-of-issuer"),
            attributes=initial_internal_attributes,
        )

        new_context, new_data = plugin.process(context, data)
        self.assertEqual(expected_internal_attributes, new_data.attributes)

    def test_missing_strategy_definition_in_attribute_derivation_strategy(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "foo": [],
                },
            }
        ]

        plugin = AttributeDeriver(
            config,
            name="AttributeDeriver",
            base_url="https://proxy.example.org",
        )

        plugin.next = lambda context, data: (context, data)
        context = Context()
        context.state = State()

        initial_internal_attributes = {
            "username": ["displayname_value"],
        }

        expected_internal_attributes = {
            "username": ["displayname_value"],
        }

        data = InternalData(
            auth_info=AuthenticationInformation(issuer="entity-id-of-issuer"),
            attributes=initial_internal_attributes,
        )

        new_context, new_data = plugin.process(context, data)
        self.assertEqual(expected_internal_attributes, new_data.attributes)


class TestAttributeDeriver(unittest.TestCase):
    def test_derived_attr_with_config_1(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "_skip_due_to_invalid_value_index_": [
                        {
                            "attr_source": "mail",
                            "clear_source": False,
                            "strategy": "set",
                            "strategy_options": {
                                "value_index": 999,
                            },
                        },
                    ],
                    "_skip_due_to_invalid_token_index_": [
                        {
                            "attr_source": "displayname",
                            "strategy": "select",
                            "strategy_options": {
                                "value_index": 0,
                                "token_index": 999,
                            },
                        },
                    ],
                    "mail": [
                        {
                            "attr_source": "mail",
                            "clear_source": False,
                            "strategy": "set",
                            "strategy_options": {
                                "value_index": 0,
                            },
                        },
                    ],
                    "foo": [
                        {"attr_source": "givenname", "strategy": "set"},
                        {
                            "attr_source": "displayname",
                            "clear_source": False,
                            "strategy": "select",
                            "strategy_options": {
                                "value_index": 0,
                                "token_index": 0,
                                "strip": [","],
                                "stopwords": [
                                    r"mr\.?",
                                    r"ms\.?",
                                    r"mrs\.?",
                                    r"dr\.?",
                                    r"the",
                                    r"de",
                                    r"la",
                                    r"the",
                                    r"[Ss]ir",
                                ],
                            },
                        },
                    ],
                    "bar": [
                        {"attr_source": "sn", "clear_source": True, "strategy": "set"},
                        {
                            "attr_source": "surname",
                            "clear_source": True,
                            "strategy": "set",
                        },
                        {
                            "attr_source": "displayname",
                            "clear_source": True,
                            "strategy": "select",
                            "strategy_options": {
                                "token_index": -1,
                                "strip": [","],
                            },
                        },
                    ],
                },
            }
        ]

        plugin = AttributeDeriver(
            config,
            name="AttributeDeriver",
            base_url="https://proxy.example.org",
        )
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        data = InternalData(
            auth_info=AuthenticationInformation(issuer="entity-id-of-issuer"),
            attributes={
                "displayname": ["dr. Alice Bob"],
                "surname": ["Alice Bob"],
                "eptid": ["edupersontargetedid_value"],
                "username": ["displayname_value"],
                "mail": ["mail_value1@example.com", "mail_value2@example.com"],
            },
        )

        data.requester = "sp"

        expected_internal_attributes = {
            "displayname": ["dr. Alice Bob"],
            "foo": ["Alice"],
            "bar": ["Alice Bob"],
            "eptid": ["edupersontargetedid_value"],
            "username": ["displayname_value"],
            "mail": ["mail_value1@example.com"],
        }
        new_context, new_data = plugin.process(context, data)
        self.assertEqual(expected_internal_attributes, new_data.attributes)

    def test_derived_attr_with_config_2(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "foo": [
                        {
                            "attr_source": "givenname",
                            "clear_source": True,
                            "strategy": "set",
                        },
                        {
                            "attr_source": "displayname",
                            "clear_source": True,
                            "strategy": "select",
                            "strategy_options": {
                                "token_index": 0,
                                "strip": [","],
                                "stopwords": [
                                    r"mr\.?",
                                    r"ms\.?",
                                    r"mrs\.?",
                                    r"dr\.?",
                                    r"the",
                                    r"de",
                                    r"la",
                                    r"the",
                                    r"[Ss]ir",
                                ],
                            },
                        },
                    ],
                    "bar": [
                        {"attr_source": "sn", "clear_source": True, "strategy": "set"},
                        {
                            "attr_source": "surname",
                            "clear_source": True,
                            "strategy": "set",
                        },
                        {
                            "attr_source": "displayname",
                            "clear_source": True,
                            "strategy": "select",
                            "strategy_options": {
                                "token_index": -1,
                                "strip": [","],
                            },
                        },
                    ],
                },
            }
        ]

        plugin = AttributeDeriver(
            config,
            name="AttributeDeriver",
            base_url="https://proxy.example.org",
        )
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        data = InternalData(
            auth_info=AuthenticationInformation(issuer="entity-id-of-issuer"),
            attributes={
                "givenname": ["dr. Alice Bob"],
                "displayname": ["Alice Bob"],
                "eptid": ["edupersontargetedid_value"],
                "username": ["displayname_value"],
                "mail": ["mail_value@example.com"],
            },
        )

        data.requester = "sp"

        expected_internal_attributes = {
            "foo": ["dr. Alice Bob"],
            "bar": ["Bob"],
            "eptid": ["edupersontargetedid_value"],
            "username": ["displayname_value"],
            "mail": ["mail_value@example.com"],
        }
        new_context, new_data = plugin.process(context, data)
        self.assertEqual(expected_internal_attributes, new_data.attributes)

    def test_select_without_strip_and_stopwords(self):
        config = [
            {
                "error_url": "https://example.org/error",
                "attribute_derivation_strategies": {
                    "foo": [
                        {
                            "attr_source": "displayname",
                            "clear_source": True,
                            "strategy": "select",
                            "strategy_options": {
                                "token_index": 1,
                            },
                        },
                    ],
                },
            }
        ]

        plugin = AttributeDeriver(
            config,
            name="AttributeDeriver",
            base_url="https://proxy.example.org",
        )
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        data = InternalData(
            auth_info=AuthenticationInformation(issuer="entity-id-of-issuer"),
            attributes={
                "givenname": ["dr. Alice Bob"],
                "displayname": ["Alice Bob"],
                "eptid": ["edupersontargetedid_value"],
                "username": ["displayname_value"],
                "mail": ["mail_value@example.com"],
            },
        )

        data.requester = "sp"

        expected_internal_attributes = {
            "givenname": ["dr. Alice Bob"],
            "foo": ["Bob"],
            "eptid": ["edupersontargetedid_value"],
            "username": ["displayname_value"],
            "mail": ["mail_value@example.com"],
        }
        new_context, new_data = plugin.process(context, data)
        self.assertEqual(expected_internal_attributes, new_data.attributes)


if __name__ == "__main__":
    unittest.main()
