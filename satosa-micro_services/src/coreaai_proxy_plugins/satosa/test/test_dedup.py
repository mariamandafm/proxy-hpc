import unittest

from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.dedup import AttributeDeduper


class RequesterAccessListAuthorizedTests(unittest.TestCase):
    def setUp(self):
        config = {}
        self.plugin = AttributeDeduper(config, "name", "baseUrl")
        self.plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        self.context = context
        self.internal_data = InternalData(requester="example_requester")

    def test_process_no_dups(self):
        self.internal_data.attributes = {
            "attrA": ["vA1"],
            "attrB": ["vB1", "vB2"],
            "attrC": ["vC1", "vC2", "vC3"],
            "attrD": [""],
            "attrE": [],
        }
        expected = {
            "attrA": ["vA1"],
            "attrB": ["vB1", "vB2"],
            "attrC": ["vC1", "vC2", "vC3"],
            "attrD": [""],
            "attrE": [],
        }

        result = self.plugin.process(self.context, self.internal_data)
        assert type(result) is tuple
        assert len(result) == 2
        context, data = result
        self.assertDictEqual(data.attributes, expected)

    def test_process_some_dups(self):
        self.internal_data.attributes = {
            "attrA": ["vA1"],
            "attrB": ["vB1", "vB1"],
            "attrC": ["vC1", "vC2", "vC3"],
        }
        expected = {
            "attrA": ["vA1"],
            "attrB": ["vB1"],
            "attrC": ["vC1", "vC2", "vC3"],
        }

        result = self.plugin.process(self.context, self.internal_data)
        assert type(result) is tuple
        assert len(result) == 2
        context, data = result
        self.assertDictEqual(data.attributes, expected)

    def test_process_all_dups(self):
        self.internal_data.attributes = {
            "attrA": ["vA1", "vA1"],
            "attrB": ["vB1", "vB1"],
            "attrC": ["vC1", "vC2", "vC1", "vC2"],
        }
        expected = {
            "attrA": ["vA1"],
            "attrB": ["vB1"],
            "attrC": ["vC1", "vC2"],
        }

        result = self.plugin.process(self.context, self.internal_data)
        assert type(result) is tuple
        assert len(result) == 2

        context, data = result
        assert (
            len(expected) == len(data.attributes)
            and all(
                sorted(v) == sorted(data.attributes.get(k))
                for k, v in expected.items()
            )
        )


if __name__ == "__main__":
    unittest.main()
