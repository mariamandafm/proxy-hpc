import unittest

import pytest

from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.attribute_exchange import AttributeExchange


class DefaultTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "": {"from-a-default-attribute": "to-another-attribute"},
            "requester-id": {"from-a-requester-attribute": "to-another-attribute"},
            "default": {
                "default": {
                    "default-default-setting-from-attribute": "default-default-setting-to-attribute"
                },
                "requester1": {
                    "default-requester1-setting-from-attribute": "default-requester1-setting-to-attribute"
                },
                "requester2": {
                    "default-requester2-setting-from-attribute": "default-requester2-setting-to-attribute"
                },
            },
            "issuer1": {
                "default": {
                    "issuer1-default-setting-from-attribute": "issuer1-default-setting-to-attribute"
                },
                "requester1": {
                    "issuer1-requester1-setting-from-attribute": "issuer1-requester1-setting-to-attribute"
                },
                "requester2": {
                    "issuer1-requester2-setting-from-attribute": "issuer1-requester2-setting-to-attribute"
                },
            },
            "issuer2": {
                "default": {
                    "issuer2-default-setting-from-attribute": "issuer2-default-setting-to-attribute"
                },
                "requester1": {
                    "issuer2-requester1-setting-from-attribute": "issuer2-requester1-setting-to-attribute"
                },
                "requester2": {
                    "issuer2-requester2-setting-from-attribute": "issuer2-requester2-setting-to-attribute"
                },
            },
            "issuer-multiple": {
                "default": {
                    "issuer-multiple-default-setting-from-attribute1": "issuer-multiple-default-setting-to-attribute1",
                    "issuer-multiple-default-setting-from-attribute2": "issuer-multiple-default-setting-to-attribute2",
                    "issuer-multiple-default-setting-from-attribute3": "issuer-multiple-default-setting-to-attribute3",
                }
            },
            "requester1": {
                "default": {
                    "requester1-default-setting-from-attribute": "requester1-default-setting-to-attribute"
                },
                "issuer1": {
                    "requester1-issuer1-setting-from-attribute": "requester1-issuer1-setting-to-attribute"
                },
                "issuer2": {
                    "requester1-issuer2-setting-from-attribute": "requester1-issuer2-setting-to-attribute"
                },
            },
        }

        plugin = AttributeExchange(
            self.config, name="name", base_url="https://example.com"
        )
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_process_with_empty_default(self):
        internal_data = InternalData(
            attributes={"from-a-default-attribute": ["default-attribute-value"]}
        )
        result = self.plugin.process(self.context, internal_data)
        assert type(result) is tuple
        assert len(result) == 2

        result_attributes = result[1].get("attributes")
        self.assertEqual(
            result_attributes,
            {
                "from-a-default-attribute": ["default-attribute-value"],
                "to-another-attribute": ["default-attribute-value"],
            },
        )

    def test_process_with_empty_default_and_requester(self):
        internal_data = InternalData(
            requester="requester-id",
            attributes={"from-a-requester-attribute": ["requester-attribute-value"]},
        )
        result = self.plugin.process(self.context, internal_data)
        assert type(result) is tuple
        assert len(result) == 2

        result_attributes = result[1].get("attributes")
        self.assertEqual(
            result_attributes,
            {
                "from-a-requester-attribute": ["requester-attribute-value"],
                "to-another-attribute": ["requester-attribute-value"],
            },
        )


@pytest.mark.parametrize(
    "entry",
    [
        {
            "issuer": "issuer-random",
            "requester": "requester-random",
            "before": {
                "default-default-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "default-default-setting-from-attribute": ["attribute-value"],
                "default-default-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer-random",
            "requester": "requester1",
            "before": {
                "default-requester1-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "default-requester1-setting-from-attribute": ["attribute-value"],
                "default-requester1-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer-random",
            "requester": "requester2",
            "before": {
                "default-requester2-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "default-requester2-setting-from-attribute": ["attribute-value"],
                "default-requester2-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer1",
            "requester": "requester-random",
            "before": {
                "issuer1-default-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "issuer1-default-setting-from-attribute": ["attribute-value"],
                "issuer1-default-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer1",
            "requester": "requester1",
            "before": {
                "issuer1-requester1-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "issuer1-requester1-setting-from-attribute": ["attribute-value"],
                "issuer1-requester1-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer1",
            "requester": "requester2",
            "before": {
                "issuer1-requester2-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "issuer1-requester2-setting-from-attribute": ["attribute-value"],
                "issuer1-requester2-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer2",
            "requester": "requester-random",
            "before": {
                "issuer2-default-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "issuer2-default-setting-from-attribute": ["attribute-value"],
                "issuer2-default-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer2",
            "requester": "requester1",
            "before": {
                "issuer2-requester1-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "issuer2-requester1-setting-from-attribute": ["attribute-value"],
                "issuer2-requester1-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer2",
            "requester": "requester2",
            "before": {
                "issuer2-requester2-setting-from-attribute": ["attribute-value"]
            },
            "after": {
                "issuer2-requester2-setting-from-attribute": ["attribute-value"],
                "issuer2-requester2-setting-to-attribute": ["attribute-value"],
            },
        },
        {
            "issuer": "issuer-multiple",
            "requester": "requester-random",
            "before": {
                "issuer-multiple-default-setting-from-attribute1": [
                    "attribute-value"
                ],
                "issuer-multiple-default-setting-from-attribute2": [
                    "attribute-value"
                ],
                "issuer-multiple-default-setting-from-attribute3": [
                    "attribute-value"
                ],
            },
            "after": {
                "issuer-multiple-default-setting-from-attribute1": [
                    "attribute-value"
                ],
                "issuer-multiple-default-setting-from-attribute2": [
                    "attribute-value"
                ],
                "issuer-multiple-default-setting-from-attribute3": [
                    "attribute-value"
                ],
                "issuer-multiple-default-setting-to-attribute1": [
                    "attribute-value"
                ],
                "issuer-multiple-default-setting-to-attribute2": [
                    "attribute-value"
                ],
                "issuer-multiple-default-setting-to-attribute3": [
                    "attribute-value"
                ],
            },
        },
    ],
)
def test_process_with_only_default_and_requester1(entry):
    context = Context()
    context.state = State()

    config = {
        "requester-id": {"from-a-requester-attribute": "to-another-attribute"},
        "default": {
            "default": {
                "default-default-setting-from-attribute": "default-default-setting-to-attribute"
            },
            "requester1": {
                "default-requester1-setting-from-attribute": "default-requester1-setting-to-attribute"
            },
            "requester2": {
                "default-requester2-setting-from-attribute": "default-requester2-setting-to-attribute"
            },
        },
        "issuer1": {
            "default": {
                "issuer1-default-setting-from-attribute": "issuer1-default-setting-to-attribute"
            },
            "requester1": {
                "issuer1-requester1-setting-from-attribute": "issuer1-requester1-setting-to-attribute"
            },
            "requester2": {
                "issuer1-requester2-setting-from-attribute": "issuer1-requester2-setting-to-attribute"
            },
        },
        "issuer2": {
            "default": {
                "issuer2-default-setting-from-attribute": "issuer2-default-setting-to-attribute"
            },
            "requester1": {
                "issuer2-requester1-setting-from-attribute": "issuer2-requester1-setting-to-attribute"
            },
            "requester2": {
                "issuer2-requester2-setting-from-attribute": "issuer2-requester2-setting-to-attribute"
            },
        },
        "issuer-multiple": {
            "default": {
                "issuer-multiple-default-setting-from-attribute1": "issuer-multiple-default-setting-to-attribute1",
                "issuer-multiple-default-setting-from-attribute2": "issuer-multiple-default-setting-to-attribute2",
                "issuer-multiple-default-setting-from-attribute3": "issuer-multiple-default-setting-to-attribute3",
            }
        },
        "requester1": {
            "default": {
                "requester1-default-setting-from-attribute": "requester1-default-setting-to-attribute"
            },
            "issuer1": {
                "requester1-issuer1-setting-from-attribute": "requester1-issuer1-setting-to-attribute"
            },
            "issuer2": {
                "requester1-issuer2-setting-from-attribute": "requester1-issuer2-setting-to-attribute"
            },
        },
    }

    plugin = AttributeExchange(
        config, name="name", base_url="https://example.com"
    )
    plugin.next = lambda context, data: (context, data)

    internal_data = InternalData(
        requester=entry["requester"],
        auth_info={"issuer": entry["issuer"]},
        attributes=entry["before"],
    )

    plugin.process(context, internal_data)
    t = unittest.TestCase()
    t.assertDictEqual(internal_data.attributes, entry["after"])


if __name__ == "__main__":
    unittest.main()
