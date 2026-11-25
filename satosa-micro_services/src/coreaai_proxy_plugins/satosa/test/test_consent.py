import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from requests.exceptions import ConnectionError

from satosa.context import Context
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services import consent as consent_mod
from coreaai_proxy_plugins.satosa.micro_services.consent import (
    Consent,
    STATE_KEY,
    UnexpectedResponseError,
    filter_items_exist,
    generate_consent_id,
    has_service_alodp,
    invoke_consent_registration,
    verify_consent,
)


SP = "https://sp.example.org"
IDP = "https://idp.example.org"
API = "https://uis.example.org"
REDIRECT = "https://uis.example.org/consent"
MODULE = "coreaai_proxy_plugins.satosa.micro_services.consent"


def _context(requester=SP):
    context = Context()
    context.state = State()
    context.state["SATOSA_BASE"] = {"requester": requester}
    return context


def _data(issuer=IDP, requester=SP, attributes=None, metadata=None):
    data = InternalData(
        auth_info=AuthenticationInformation(issuer=issuer),
        requester=requester,
        attributes=attributes if attributes is not None else {},
    )
    data.metadata = metadata if metadata is not None else {}
    return data


def _config(sign_key_path, **overrides):
    default = {
        "api_url": API,
        "redirect_url": REDIRECT,
        "sign_key": sign_key_path,
        "authorizations_state_key": "authorizations",
    }
    default.update(overrides)
    return {"default": default}


def _make_rsa_key_file():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    fd, path = tempfile.mkstemp(suffix=".pem")
    os.write(fd, pem)
    os.close(fd)
    return path


class ConsentHelpers(unittest.TestCase):
    def test_filter_items_exist_keeps_only_listed_keys(self):
        self.assertEqual({"a": 1}, filter_items_exist({"a": 1, "b": 2}, ["a"]))

    def test_filter_items_exist_empty_keep_drops_all(self):
        self.assertEqual({}, filter_items_exist({"a": 1}, []))

    def test_generate_consent_id_is_deterministic(self):
        first = generate_consent_id(SP, {"x": ["1"]}, authorizations=["s"])
        second = generate_consent_id(SP, {"x": ["1"]}, authorizations=["s"])
        self.assertEqual(first, second)

    def test_generate_consent_id_depends_on_requester(self):
        self.assertNotEqual(
            generate_consent_id("sp1", {"x": ["1"]}),
            generate_consent_id("sp2", {"x": ["1"]}),
        )

    def test_generate_consent_id_uses_attribute_names_not_values(self):
        self.assertEqual(
            generate_consent_id(SP, {"x": ["1"]}),
            generate_consent_id(SP, {"x": ["2"]}),
        )

    def test_has_service_alodp_for_marked_service(self):
        self.assertTrue(has_service_alodp(SP, None, {SP: True}))

    def test_has_service_alodp_for_adequate_country(self):
        code = next(
            iter(consent_mod.iso3166.countries_w_adequate_level_of_data_protection)
        )
        self.assertTrue(has_service_alodp(SP, code, {}))

    def test_has_service_alodp_false_otherwise(self):
        self.assertFalse(has_service_alodp(SP, "ZZ", {}))


class ConsentNetworkHelpers(unittest.TestCase):
    @patch(f"{MODULE}.requests.get")
    def test_verify_consent_returns_attributes_on_200(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, text='["a", "b"]')

        self.assertEqual(["a", "b"], verify_consent(API, "cid"))
        mock_get.assert_called_once_with(f"{API}/verify/cid")

    @patch(f"{MODULE}.requests.get")
    def test_verify_consent_returns_none_on_non_200(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)

        self.assertIsNone(verify_consent(API, "cid"))

    @patch(f"{MODULE}.requests.post")
    @patch(f"{MODULE}.JWS")
    def test_invoke_consent_registration_returns_ticket(self, mock_jws, mock_post):
        mock_jws.return_value.sign_compact.return_value = "signed-jwt"
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"ticket": "TICKET"}
        )

        ticket = invoke_consent_registration(API, MagicMock(alg="RS256"), {"a": 1})

        self.assertEqual("TICKET", ticket)
        mock_post.assert_called_once_with(f"{API}/creq", json={"jwt": "signed-jwt"})

    @patch(f"{MODULE}.requests.post")
    @patch(f"{MODULE}.JWS")
    def test_invoke_consent_registration_raises_on_non_200(self, mock_jws, mock_post):
        mock_jws.return_value.sign_compact.return_value = "signed-jwt"
        mock_post.return_value = MagicMock(status_code=500, text="boom")

        with self.assertRaises(UnexpectedResponseError):
            invoke_consent_registration(API, MagicMock(alg="RS256"), {"a": 1})


class ConsentParseConfig(unittest.TestCase):
    def _plugin(self, config):
        plugin = Consent(config, {}, "name", "https://proxy.example.org")
        plugin.next = lambda context, data: "NEXT"
        return plugin

    def test_uses_default_when_no_override(self):
        plugin = self._plugin({"default": {"api_url": "default"}})
        config = plugin._parse_config(plugin.config, _context(), _data())
        self.assertEqual("default", config["api_url"])

    def test_empty_string_key_is_treated_as_default(self):
        plugin = self._plugin({"": {"api_url": "default"}})
        config = plugin._parse_config(plugin.config, _context(), _data())
        self.assertEqual("default", config["api_url"])

    def test_per_idp_override(self):
        plugin = self._plugin(
            {"default": {"api_url": "default"}, IDP: {"api_url": "idp"}}
        )
        config = plugin._parse_config(plugin.config, _context(), _data())
        self.assertEqual("idp", config["api_url"])

    def test_per_sp_override(self):
        plugin = self._plugin(
            {"default": {"api_url": "default"}, SP: {"api_url": "sp"}}
        )
        config = plugin._parse_config(plugin.config, _context(), _data())
        self.assertEqual("sp", config["api_url"])

    def test_sp_override_wins_over_idp(self):
        plugin = self._plugin(
            {
                "default": {"api_url": "default"},
                IDP: {"api_url": "idp"},
                SP: {"api_url": "sp"},
            }
        )
        config = plugin._parse_config(plugin.config, _context(), _data())
        self.assertEqual("sp", config["api_url"])

    def test_both_default_and_empty_string_returns_next(self):
        plugin = self._plugin({"default": {}, "": {}})
        self.assertEqual("NEXT", plugin._parse_config(plugin.config, _context(), _data()))

    def test_no_default_returns_next(self):
        plugin = self._plugin({"api_url": "x"})
        self.assertEqual("NEXT", plugin._parse_config(plugin.config, _context(), _data()))

    def test_missing_requester_returns_next(self):
        plugin = self._plugin({"default": {"api_url": "default"}})
        context = Context()
        context.state = State()  # no SATOSA_BASE entry
        self.assertEqual(
            "NEXT", plugin._parse_config(plugin.config, context, _data())
        )


class ConsentProcess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_path = _make_rsa_key_file()

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.key_path)

    def _plugin(self, internal_attributes=None, **config_overrides):
        plugin = Consent(
            _config(self.key_path, **config_overrides),
            internal_attributes or {},
            "name",
            "https://proxy.example.org",
        )
        plugin.next = lambda context, data: (context, data)
        return plugin

    @patch(f"{MODULE}.verify_consent")
    def test_existing_consent_filters_and_ends(self, mock_verify):
        mock_verify.return_value = ["attr1"]
        plugin = self._plugin()
        context = _context()
        data = _data(attributes={"attr1": ["v"], "attr2": ["w"]})

        plugin.process(context, data)

        self.assertEqual({"attr1": ["v"]}, data.attributes)
        self.assertNotIn(STATE_KEY, context.state)

    @patch(f"{MODULE}.invoke_consent_registration")
    @patch(f"{MODULE}.verify_consent")
    def test_no_consent_redirects_to_user_info_service(self, mock_verify, mock_invoke):
        mock_verify.return_value = None
        mock_invoke.return_value = "TICKET"
        plugin = self._plugin(internal_attributes={"user_id_to_attr": "subject-id"})
        context = _context()
        data = _data(attributes={"attr1": ["v"]})

        result = plugin.process(context, data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(f"{REDIRECT}/TICKET", result.message)
        self.assertIn("internal_resp", context.state[STATE_KEY])

    @patch(f"{MODULE}.verify_consent")
    def test_user_info_service_unreachable_drops_attributes(self, mock_verify):
        mock_verify.side_effect = ConnectionError("down")
        plugin = self._plugin()
        context = _context()
        data = _data(attributes={"attr1": ["v"]})

        plugin.process(context, data)

        self.assertEqual({}, data.attributes)

    @patch(f"{MODULE}.invoke_consent_registration")
    @patch(f"{MODULE}.verify_consent")
    def test_registration_failure_drops_attributes(self, mock_verify, mock_invoke):
        mock_verify.return_value = None
        mock_invoke.side_effect = UnexpectedResponseError("boom")
        plugin = self._plugin()
        context = _context()
        data = _data(attributes={"attr1": ["v"]})

        plugin.process(context, data)

        self.assertEqual({}, data.attributes)

    @patch(f"{MODULE}.invoke_consent_registration")
    @patch(f"{MODULE}.verify_consent")
    def test_enforce_consent_skips_verification(self, mock_verify, mock_invoke):
        mock_invoke.return_value = "TICKET"
        plugin = self._plugin(enforce_consent=True)
        context = _context()
        data = _data(attributes={"attr1": ["v"]})

        result = plugin.process(context, data)

        self.assertIsInstance(result, Redirect)
        mock_verify.assert_not_called()

    @patch(f"{MODULE}.invoke_consent_registration")
    @patch(f"{MODULE}.verify_consent")
    def test_no_consent_forwards_requester_logo(self, mock_verify, mock_invoke):
        mock_verify.return_value = None
        mock_invoke.return_value = "TICKET"
        plugin = self._plugin()
        context = _context()
        context.state[STATE_KEY] = {"requester_logo": "logo.png"}
        data = _data(attributes={"attr1": ["v"]})

        plugin.process(context, data)

        _api, _key, consent_args = mock_invoke.call_args[0]
        self.assertEqual("logo.png", consent_args["requester_logo"])

    def test_empty_config_passes_through(self):
        plugin = Consent({"default": {}}, {}, "name", "https://proxy.example.org")
        plugin.next = lambda context, data: (context, data)
        context = _context()
        data = _data(attributes={"attr1": ["v"]})

        plugin.process(context, data)

        self.assertEqual({"attr1": ["v"]}, data.attributes)


class ConsentHandleResponse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_path = _make_rsa_key_file()

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.key_path)

    def _plugin(self):
        plugin = Consent(_config(self.key_path), {}, "name", "https://proxy.example.org")
        plugin.next = lambda context, data: (context, data)
        return plugin

    @patch(f"{MODULE}.verify_consent")
    def test_consent_given_filters_attributes(self, mock_verify):
        mock_verify.return_value = ["attr1"]
        plugin = self._plugin()
        context = _context()
        saved = _data(attributes={"attr1": ["v"], "attr2": ["w"]})
        context.state[STATE_KEY] = {"internal_resp": saved.to_dict()}

        _context_out, data_out = plugin._handle_consent_response(context)

        self.assertEqual({"attr1": ["v"]}, data_out.attributes)
        self.assertNotIn(STATE_KEY, context.state)

    @patch(f"{MODULE}.verify_consent")
    def test_consent_not_given_drops_attributes(self, mock_verify):
        mock_verify.return_value = None
        plugin = self._plugin()
        context = _context()
        saved = _data(attributes={"attr1": ["v"], "attr2": ["w"]})
        context.state[STATE_KEY] = {"internal_resp": saved.to_dict()}

        _context_out, data_out = plugin._handle_consent_response(context)

        self.assertEqual({}, data_out.attributes)

    @patch(f"{MODULE}.verify_consent")
    def test_user_info_service_unreachable_drops_attributes(self, mock_verify):
        mock_verify.side_effect = ConnectionError("down")
        plugin = self._plugin()
        context = _context()
        saved = _data(attributes={"attr1": ["v"], "attr2": ["w"]})
        context.state[STATE_KEY] = {"internal_resp": saved.to_dict()}

        _context_out, data_out = plugin._handle_consent_response(context)

        self.assertEqual({}, data_out.attributes)

    def test_empty_config_passes_through(self):
        plugin = Consent({"default": {}}, {}, "name", "https://proxy.example.org")
        plugin.next = lambda context, data: (context, data)
        context = _context()
        saved = _data(attributes={"attr1": ["v"]})
        context.state[STATE_KEY] = {"internal_resp": saved.to_dict()}

        _context_out, data_out = plugin._handle_consent_response(context)

        self.assertEqual({"attr1": ["v"]}, data_out.attributes)


class ConsentEndpoints(unittest.TestCase):
    def test_register_endpoints(self):
        plugin = Consent({}, {}, "name", "https://proxy.example.org")

        endpoints = plugin.register_endpoints()

        self.assertEqual(1, len(endpoints))
        regex, handler = endpoints[0]
        self.assertEqual("^consent/handle_consent$", regex)
        self.assertEqual(plugin._handle_consent_response, handler)


if __name__ == "__main__":
    unittest.main()
