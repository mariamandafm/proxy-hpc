import hashlib
import unittest

from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.context import Context
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.nameid_processor import (
    NameIDProcessor,
    NameIDProcessorError,
    create_hasher,
)


SP = "https://sp.example.org"
PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"


def _plugin(config):
    plugin = NameIDProcessor(config, "", "", "")
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context():
    context = Context()
    context.state = State()
    return context


def _data(attributes=None, requester=SP, subject_id="orig-id"):
    data = InternalData()
    data.auth_info = AuthenticationInformation("", None, "https://idp.example.org")
    data.requester = requester
    data.attributes = attributes or {}
    data.subject_id = subject_id
    return data


class NameIDProcessorValidation(unittest.TestCase):
    def test_valid_config_builds(self):
        # Does not raise.
        _plugin({SP: {"scope": "@example.com"}})

    def test_invalid_nameid_format_raises(self):
        with self.assertRaises(NameIDProcessorError):
            _plugin({SP: {"nameid-format": 123}})

    def test_attributes_as_string_raises(self):
        with self.assertRaises(NameIDProcessorError):
            _plugin({SP: {"attributes": "abc"}})

    def test_scope_without_leading_at_raises(self):
        with self.assertRaises(NameIDProcessorError):
            _plugin({SP: {"scope": "example.com"}})

    def test_hash_without_salt_raises(self):
        with self.assertRaises(NameIDProcessorError):
            _plugin({SP: {"hash": {"alg": "sha512"}}})

    def test_hash_without_alg_raises(self):
        with self.assertRaises(NameIDProcessorError):
            _plugin({SP: {"hash": {"salt": "s"}}})

    def test_config_without_any_setting_raises(self):
        with self.assertRaises(NameIDProcessorError):
            _plugin({"": {}})


class NameIDProcessorProcess(unittest.TestCase):
    def setUp(self):
        self.context = _context()

    def test_sets_nameid_format(self):
        plugin = _plugin({SP: {"nameid-format": PERSISTENT}})
        data = _data(subject_id="orig-id")

        plugin.process(self.context, data)

        self.assertEqual(PERSISTENT, data.subject_type)
        self.assertEqual("orig-id", data.subject_id)

    def test_builds_subject_id_from_attributes_in_order(self):
        plugin = _plugin({SP: {"attributes": ["a", "b"]}})
        data = _data({"a": ["X"], "b": ["Y"]})

        plugin.process(self.context, data)

        self.assertEqual("XY", data.subject_id)

    def test_missing_attribute_values_raises(self):
        plugin = _plugin({SP: {"attributes": ["a"]}})
        data = _data({})

        with self.assertRaises(NameIDProcessorError):
            plugin.process(self.context, data)

    def test_hashes_subject_id(self):
        plugin = _plugin(
            {SP: {"attributes": ["a"], "hash": {"salt": "s", "alg": "sha256"}}}
        )
        data = _data({"a": ["uid"]})

        plugin.process(self.context, data)

        expected = hashlib.sha256(b"s" + b"uid").hexdigest()
        self.assertEqual(expected, data.subject_id)

    def test_adds_scope(self):
        plugin = _plugin({SP: {"attributes": ["a"], "scope": "@example.com"}})
        data = _data({"a": ["uid"]})

        plugin.process(self.context, data)

        self.assertEqual("uid@example.com", data.subject_id)

    def test_hash_then_scope_combined(self):
        plugin = _plugin(
            {
                SP: {
                    "attributes": ["a"],
                    "hash": {"salt": "s", "alg": "sha256"},
                    "scope": "@example.com",
                }
            }
        )
        data = _data({"a": ["uid"]})

        plugin.process(self.context, data)

        expected = hashlib.sha256(b"s" + b"uid").hexdigest() + "@example.com"
        self.assertEqual(expected, data.subject_id)

    def test_default_applies_to_unconfigured_requester(self):
        plugin = _plugin({SP: {"scope": "@sp"}})
        data = _data({"a": ["uid"]}, requester="https://other-sp.example.org",
                     subject_id="orig-id")

        plugin.process(self.context, data)

        # falls back to the (empty) default -> no changes
        self.assertEqual("orig-id", data.subject_id)

    def test_explicit_default_via_empty_key(self):
        plugin = _plugin({"": {"scope": "@default"}, SP: {"scope": "@sp"}})
        data = _data(requester="https://other-sp.example.org", subject_id="orig-id")

        plugin.process(self.context, data)

        self.assertEqual("orig-id@default", data.subject_id)


class NameIDProcessorHasher(unittest.TestCase):
    def test_hasher_matches_hashlib(self):
        hasher = create_hasher("salt", alg="sha256")
        self.assertEqual(
            hashlib.sha256(b"salt" + b"value").hexdigest(), hasher("value")
        )

    def test_hasher_is_deterministic(self):
        hasher = create_hasher("salt")
        self.assertEqual(hasher("value"), hasher("value"))

    def test_different_salt_changes_output(self):
        self.assertNotEqual(
            create_hasher("salt-a")("value"), create_hasher("salt-b")("value")
        )

    def test_default_algorithm_is_sha512(self):
        self.assertEqual(
            hashlib.sha512(b"salt" + b"value").hexdigest(),
            create_hasher("salt")("value"),
        )

    def test_accepts_bytes_salt_and_value(self):
        self.assertEqual(
            create_hasher("salt")("value"),
            create_hasher(b"salt")(b"value"),
        )


if __name__ == "__main__":
    unittest.main()
