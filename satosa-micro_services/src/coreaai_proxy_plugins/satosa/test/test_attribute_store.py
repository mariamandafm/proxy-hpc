import json

from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock

from ldap3.core.exceptions import LDAPException
from requests import Response
from satosa.internal import AuthenticationInformation
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.helpers.perun.rpc.errors import Error as PerunError
from coreaai_proxy_plugins.satosa.micro_services.attribute_store import (
    AttributeStore,
    Error,
)

MODULE = "coreaai_proxy_plugins.satosa.micro_services.attribute_store"


class AttributeStoreTests(TestCase):
    def setUp(self):
        config = {
            "default": {
                "ordered_identifier_candidates": [
                    {
                        "attribute_names": ["vopersonsorid"]
                    },
                ],
                "look_up_strategy": "api",
                "api_url": "https://perun.unitest.example.org/ba/rpc/json/",
                "api_auth_user": "registryadmin",
                "api_auth_password": "secret",
                "api_timeout": 3,
                "search_return_attributes": {
                    "urn:perun:user:attribute-def:core:lastName": [
                        "surname"
                    ],
                    "urn:perun:user:attribute-def:core:firstName": [
                        "givenname"
                    ],
                    "urn:perun:user:attribute-def:def:preferredMail": [
                        "mail",
                        "vopersonverifiedemail"
                    ]
                },
                "eppn_attr": "eppn",
                "eppn_scope": "scope-value.tld",
                "attr_internal_cuid": "vopersonid",
                "attr_internal_cuid_preset": "__eas_internal_cuid__vopersonid",
                "ext_source_name": "https://proxy.test.example.org/proxy"
            }
        }

        data = InternalData(
            requester="service-to-be-processed",
            auth_info=AuthenticationInformation("", None, "issuer-user-authenticated-with"),
        )

        metadata = {
            "service-to-be-processed": {
                "display_name": "service to be processed display name"
            },
            "issuer-user-authenticated-with": {
                "display_name": "issuer user authenticated with display name"
            },
        }

        data.metadata = metadata
        context = Context()
        state = State("_Td6WFoAAATm1rRGAgAhARYAAAB0L-Wj4AC_ALhdADqayKyxlWEA-Vbuhpv0jURbND89wcfhecCUTqDMA_Yb4jR4NXs-YDl"
                      "t12UoDn2M_brtri_vBMPAtVx1GlsFsEaKZAt0xUQy92yc9gb4bBNHO48u9zmHmu26jdkA7rRJ9AlnhB3nkskLClfzXRKv3Q"
                      "JWNWNk6HxDDprPxP9MP4IO_z6f5Zv4UatEugb9uB9DLe0ZKa2sxs2KosVyl5veHDb1YjwG1ON7jqda84ChxYyadFkYRYEAz"
                      "gAA-2I-gM4rldkAAdQBwAEAAGUnFQCxxGf7AgAAAAAEWVo=", "secret")
        context.state = state

        plugin = AttributeStore(
            config,
            name="AttributeStore",
            base_url="https://proxy.example.org",
        )

        plugin.next = lambda context, data: (context, data)
        self.config = config
        self.context = context
        self.data = data
        self.plugin = plugin

    @patch("coreaai_proxy_plugins.satosa.micro_services.attribute_store.create_http_client_session.post")
    def test_attribute_store_successful_flow(self, create_http_client_session_mock):
        get_attributes_response = Response()
        response_str = json.dumps(
            [
                {
                    "id": 16,
                    "createdAt": "2020-04-03 15:19:13.6948",
                    "createdBy": "perun",
                    "modifiedAt": "2020-04-03 15:19:13.6948",
                    "modifiedBy": "perun",
                    "createdByUid": "None",
                    "modifiedByUid": "None",
                    "friendlyName": "firstName",
                    "namespace": "urn:perun:user:attribute-def:core",
                    "description": "None",
                    "type": "java.lang.String",
                    "displayName": "User first name",
                    "writable": True,
                    "unique": False,
                    "value": "Master",
                    "valueCreatedAt": "None",
                    "valueCreatedBy": "None",
                    "valueModifiedAt": "None",
                    "valueModifiedBy": "None",
                    "entity": "user",
                    "baseFriendlyName": "firstName",
                    "friendlyNameParameter": "",
                    "beanName": "Attribute"
                },
                {
                    "id": 47,
                    "createdAt": "2020-04-03 15:19:13.6948",
                    "createdBy": "perun",
                    "modifiedAt": "2020-04-03 15:19:13.6948",
                    "modifiedBy": "perun",
                    "createdByUid": "None",
                    "modifiedByUid": "None",
                    "friendlyName": "lastName",
                    "namespace": "urn:perun:user:attribute-def:core",
                    "description": "None",
                    "type": "java.lang.String",
                    "displayName": "User last name",
                    "writable": True,
                    "unique": False,
                    "value": "Perun",
                    "valueCreatedAt": "None",
                    "valueCreatedBy": "None",
                    "valueModifiedAt": "None",
                    "valueModifiedBy": "None",
                    "entity": "user",
                    "baseFriendlyName": "lastName",
                    "friendlyNameParameter": "",
                    "beanName": "Attribute"
                },
                {
                    "id": 56,
                    "createdAt": "2020-04-03 15:24:11.824425",
                    "createdBy": "attributesManagerBlImplInitializator",
                    "modifiedAt": "2020-04-03 15:24:11.824425",
                    "modifiedBy": "attributesManagerBlImplInitializator",
                    "createdByUid": -1,
                    "modifiedByUid": -1,
                    "friendlyName": "preferredMail",
                    "namespace": "urn:perun:user:attribute-def:def",
                    "description": "E-mail address preferred for communication.",
                    "type": "java.lang.String",
                    "displayName": "Preferred mail",
                    "writable": True,
                    "unique": False,
                    "value": "master@example.com",
                    "valueCreatedAt": "2021-04-13 10:14:39.83638",
                    "valueCreatedBy": "perunRegistrar",
                    "valueModifiedAt": "2023-03-24 07:01:43.28294",
                    "valueModifiedBy": "registryadmin",
                    "entity": "user",
                    "baseFriendlyName": "preferredMail",
                    "friendlyNameParameter": "",
                    "beanName": "Attribute"
                }
            ]
        )
        get_attributes_response._content = bytes(response_str, 'utf-8')
        get_user_response = Response()
        response_str = json.dumps(
            {
                "id": 1,
                "createdAt": "2020-04-03 15:19:13.6948",
                "createdBy": "perun",
                "modifiedAt": "2020-04-03 15:19:13.6948",
                "modifiedBy": "perun",
                "createdByUid": "None",
                "modifiedByUid": "None",
                "firstName": "Master",
                "lastName": "Perun",
                "middleName": "None",
                "titleBefore": "None",
                "titleAfter": "None",
                "serviceUser": False,
                "sponsoredUser": False,
                "uuid": "7828ef5e-6597-44b5-a866-f54226b31c56",
                "majorSpecificType": "NORMAL",
                "specificUser": False
            }
        )
        get_user_response._content = bytes(response_str, 'utf-8')
        create_http_client_session_mock.side_effect = Mock(side_effect=[get_user_response, get_attributes_response])

        self.data.attributes = {
            "vopersonid": ["e5af4c42943c2a90fb79f6be4b25416a5a280101@example.org"],
        }

        data = self.plugin.process(self.context, self.data)
        expected_internal_attributes = {'givenname': ['Master'],
                                        'surname': ['Perun'],
                                        'vopersonid':
                                        ['e5af4c42943c2a90fb79f6be4b25416a5a280101@example.org'],
                                        'mail': ['master@example.com'],
                                        'vopersonverifiedemail': ['master@example.com']}
        self.assertTrue(data[1]["attributes"] == expected_internal_attributes)


# --------------------------------------------------------------------------- #
# helpers for the process-side tests (the userinfo endpoint is out of scope)
# --------------------------------------------------------------------------- #
SP = "https://sp.example.org"
IDP = "https://idp.example.org"


def _api_config(**default_overrides):
    default = {
        "look_up_strategy": "api",
        "api_url": "https://perun.example.org/rpc/",
        "api_auth_user": "user",
        "api_auth_password": "secret",
        "api_timeout": 3,
        "ext_source_name": "https://proxy.example.org/proxy",
        "search_return_attributes": {
            "urn:perun:user:attribute-def:core:firstName": ["givenname"],
        },
        "eppn_attr": "eppn",
        "eppn_scope": "",
        "attr_internal_cuid": "vopersonid",
        "attr_internal_cuid_preset": "__preset__",
    }
    default.update(default_overrides)
    return {"default": default}


def _ldap_config(**default_overrides):
    default = {
        "look_up_strategy": "ldap",
        "ldap_url": "ldap://ldap.example.org",
        "bind_dn": "cn=bind",
        "bind_password": "pw",
        "search_base": "dc=example,dc=org",
        "ldap_identifier_attribute": "uid",
        "ordered_identifier_candidates": [{"attribute_names": ["uid"]}],
        "search_return_attributes": {"cn": ["displayName"]},
        "eppn_attr": "eppn",
        "eppn_scope": "",
    }
    default.update(default_overrides)
    return {"default": default}


def _build_api(config):
    plugin = AttributeStore(
        config, name="EAS", base_url="https://proxy.example.org"
    )
    plugin.next = lambda context, data: (context, data)
    return plugin


def _build_ldap(config, connection=None):
    conn = connection if connection is not None else MagicMock()
    with patch.object(
        AttributeStore, "_ldap_connection_factory", return_value=conn
    ):
        plugin = AttributeStore(
            config, name="EAS", base_url="https://proxy.example.org"
        )
    plugin.next = lambda context, data: (context, data)
    return plugin, conn


def _context(requester=SP):
    context = Context()
    context.state = State()
    context.state["SATOSA_BASE"] = {"requester": requester}
    return context


def _data(attributes=None):
    data = InternalData(
        requester=SP,
        auth_info=AuthenticationInformation("", None, IDP),
    )
    data.attributes = attributes if attributes is not None else {}
    return data


class AttributeStoreInit(TestCase):
    def test_requires_default_configuration(self):
        with self.assertRaises(Error):
            AttributeStore({"sp": {}}, name="x", base_url="y")

    def test_default_and_empty_string_both_present_raises(self):
        with self.assertRaises(Error):
            AttributeStore({"default": {}, "": {}}, name="x", base_url="y")

    def test_empty_string_is_treated_as_default(self):
        plugin = _build_api({"": _api_config()["default"]})
        self.assertIn("default", plugin.config)

    def test_non_dict_sp_value_raises(self):
        config = {"default": _api_config()["default"], "sp": "not-a-dict"}
        with self.assertRaises(Error):
            AttributeStore(config, name="x", base_url="y")

    def test_api_strategy_requires_ext_source_name(self):
        config = _api_config()
        del config["default"]["ext_source_name"]
        with self.assertRaises(Error):
            AttributeStore(config, name="x", base_url="y")

    def test_invalid_lookup_strategy_raises(self):
        config = _api_config(look_up_strategy="carrier-pigeon")
        with self.assertRaises(Error):
            AttributeStore(config, name="x", base_url="y")

    def test_ldap_connection_is_reused_for_matching_params(self):
        config = _ldap_config()
        config[SP] = dict(config["default"])  # identical LDAP params
        plugin, _conn = _build_ldap(config)

        self.assertIs(
            plugin.config["default"]["connection"], plugin.config[SP]["connection"]
        )

    def test_ldap_factory_failure_is_logged_not_raised(self):
        config = _ldap_config()
        config[SP] = dict(config["default"])
        with patch.object(
            AttributeStore,
            "_ldap_connection_factory",
            side_effect=Error("x"),
        ):
            plugin = AttributeStore(config, name="x", base_url="y")

        self.assertNotIn("connection", plugin.config["default"])


class AttributeStoreProcessApi(TestCase):
    @patch(f"{MODULE}.get_attrs")
    @patch(f"{MODULE}.get_user")
    def test_successful_flow_populates_attributes(self, mock_get_user, mock_get_attrs):
        mock_get_user.return_value = {"id": 1}
        mock_get_attrs.return_value = [
            {
                "namespace": "urn:perun:user:attribute-def:core",
                "friendlyName": "firstName",
                "value": "Master",
            }
        ]
        plugin = _build_api(_api_config())
        data = _data({"vopersonid": ["cuid-1"]})

        _context_out, data_out = plugin.process(_context(), data)

        self.assertEqual(["Master"], data_out.attributes["givenname"])

    @patch(f"{MODULE}.get_user")
    def test_no_cuid_passes_through(self, mock_get_user):
        plugin = _build_api(_api_config())
        data = _data({})

        plugin.process(_context(), data)

        mock_get_user.assert_not_called()

    @patch(f"{MODULE}.get_attrs")
    @patch(f"{MODULE}.get_user")
    def test_cuid_preset_sets_internal_cuid(self, mock_get_user, mock_get_attrs):
        mock_get_user.return_value = {"id": 1}
        mock_get_attrs.return_value = []
        plugin = _build_api(_api_config())
        data = _data({"__preset__": ["preset-cuid"]})

        plugin.process(_context(), data)

        self.assertEqual(["preset-cuid"], data.attributes["vopersonid"])

    @patch(f"{MODULE}.get_user")
    def test_ignore_passes_through(self, mock_get_user):
        plugin = _build_api(_api_config(ignore=True))
        data = _data({"vopersonid": ["cuid-1"]})

        plugin.process(_context(), data)

        mock_get_user.assert_not_called()

    @patch(f"{MODULE}.get_user")
    def test_missing_requester_passes_through(self, mock_get_user):
        plugin = _build_api(_api_config())
        context = Context()
        context.state = State()  # no SATOSA_BASE entry
        data = _data({"vopersonid": ["cuid-1"]})

        plugin.process(context, data)

        mock_get_user.assert_not_called()

    @patch(f"{MODULE}.get_user")
    def test_perun_error_propagates(self, mock_get_user):
        mock_get_user.side_effect = PerunError("boom")
        plugin = _build_api(_api_config())
        data = _data({"vopersonid": ["cuid-1"]})

        with self.assertRaises(Exception):
            plugin.process(_context(), data)

    @patch(f"{MODULE}.get_attrs", return_value=[])
    @patch(f"{MODULE}.get_user", return_value={"id": 1})
    def test_per_sp_override_selected(self, mock_get_user, _mock_get_attrs):
        # default ignores the SP; a per-SP override (inheriting the default)
        # re-enables processing for that requester.
        config = _api_config(ignore=True)
        sp_override = dict(config["default"])
        sp_override["ignore"] = False
        config[SP] = sp_override
        plugin = _build_api(config)

        plugin.process(_context(requester=SP), _data({"vopersonid": ["cuid-1"]}))

        mock_get_user.assert_called()


class AttributeStoreProcessLdap(TestCase):
    def test_successful_flow_populates_attributes(self):
        conn = MagicMock()
        conn.search.return_value = "msg-1"
        conn.get_response.return_value = (
            [{"dn": "uid=u,dc=example,dc=org", "attributes": {"cn": ["Master Perun"]}}],
            "status",
        )
        plugin, _conn = _build_ldap(_ldap_config(), connection=conn)
        data = _data({"uid": ["user-1"]})

        _context_out, data_out = plugin.process(_context(), data)

        self.assertEqual(["Master Perun"], data_out.attributes["displayName"])

    def test_cuid_preset_skips_lookup(self):
        conn = MagicMock()
        config = _ldap_config(
            attr_internal_cuid_preset="__preset__", attr_internal_cuid="vopersonid"
        )
        plugin, _conn = _build_ldap(config, connection=conn)
        data = _data({"__preset__": ["c-1"]})

        plugin.process(_context(), data)

        self.assertEqual(["c-1"], data.attributes["vopersonid"])
        conn.search.assert_not_called()

    def test_no_record_with_registration_url_redirects(self):
        conn = MagicMock()
        conn.search.return_value = "msg-1"
        conn.get_response.return_value = ([], "status")
        config = _ldap_config(
            on_ldap_search_result_empty="https://register.example.org/new"
        )
        plugin, _conn = _build_ldap(config, connection=conn)
        data = _data({"uid": ["user-1"]})

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertIn("register.example.org", result.message)

    def test_multiple_records_passes_through(self):
        conn = MagicMock()
        conn.search.return_value = "msg-1"
        record = {"dn": "x", "attributes": {"cn": ["a"]}}
        conn.get_response.return_value = ([record, record], "status")
        plugin, _conn = _build_ldap(_ldap_config(), connection=conn)
        data = _data({"uid": ["user-1"]})

        _context_out, data_out = plugin.process(_context(), data)

        self.assertNotIn("displayName", data_out.attributes)

    def test_clear_input_attributes_keeps_exceptions(self):
        conn = MagicMock()
        conn.search.return_value = "msg-1"
        conn.get_response.return_value = (
            [{"dn": "x", "attributes": {"cn": ["Found"]}}],
            "status",
        )
        config = _ldap_config(
            clear_input_attributes=True, clear_input_attributes_except=["uid"]
        )
        plugin, _conn = _build_ldap(config, connection=conn)
        data = _data({"uid": ["user-1"], "old_attr": ["x"]})

        _context_out, data_out = plugin.process(_context(), data)

        self.assertNotIn("old_attr", data_out.attributes)
        self.assertIn("uid", data_out.attributes)
        self.assertEqual(["Found"], data_out.attributes["displayName"])

    def test_flow_without_eppn_config(self):
        # eppn_attr/eppn_scope are optional; omitting them must not raise KeyError.
        conn = MagicMock()
        conn.search.return_value = "msg-1"
        conn.get_response.return_value = (
            [{"dn": "x", "attributes": {"cn": ["Found"]}}],
            "status",
        )
        config = _ldap_config()
        del config["default"]["eppn_attr"]
        del config["default"]["eppn_scope"]
        plugin, _conn = _build_ldap(config, connection=conn)
        data = _data({"uid": ["u1"]})

        _context_out, data_out = plugin.process(_context(), data)

        self.assertEqual(["Found"], data_out.attributes["displayName"])

    def test_no_record_without_registration_url_passes_through(self):
        # An empty LDAP result with no on_ldap_search_result_empty passes the
        # request through unchanged (previously raised AttributeError, bug B).
        conn = MagicMock()
        conn.search.return_value = "msg-1"
        conn.get_response.return_value = ([], "status")
        plugin, _conn = _build_ldap(_ldap_config(), connection=conn)
        data = _data({"uid": ["user-1"]})

        _context_out, data_out = plugin.process(_context(), data)

        self.assertIs(data, data_out)
        self.assertEqual({"uid": ["user-1"]}, data_out.attributes)

    def test_search_exception_propagates(self):
        conn = MagicMock()
        conn.search.side_effect = LDAPException("boom")
        plugin, _conn = _build_ldap(_ldap_config(), connection=conn)
        data = _data({"uid": ["user-1"]})

        with self.assertRaises(Exception):
            plugin.process(_context(), data)


class AttributeStoreLdapFactory(TestCase):
    def _plugin(self):
        return _build_api(_api_config())

    def _factory_config(self, **overrides):
        config = {
            "ldap_url": "ldap://ldap.example.org",
            "bind_dn": "cn=bind",
            "bind_password": "pw",
            "pool_size": 10,
            "pool_keepalive": 10,
        }
        config.update(overrides)
        return config

    def test_missing_ldap_url_raises(self):
        with self.assertRaises(Error):
            self._plugin()._ldap_connection_factory(self._factory_config(ldap_url=None))

    def test_missing_bind_dn_raises(self):
        with self.assertRaises(Error):
            self._plugin()._ldap_connection_factory(self._factory_config(bind_dn=None))

    def test_missing_bind_password_raises(self):
        with self.assertRaises(Error):
            self._plugin()._ldap_connection_factory(
                self._factory_config(bind_password=None)
            )

    @patch(f"{MODULE}.ldap3")
    def test_creates_connection(self, mock_ldap3):
        mock_ldap3.Connection.return_value = "the-connection"

        result = self._plugin()._ldap_connection_factory(self._factory_config())

        self.assertEqual("the-connection", result)

    @patch(f"{MODULE}.ldap3")
    def test_ldap_exception_is_wrapped(self, mock_ldap3):
        mock_ldap3.Connection.side_effect = LDAPException("down")

        with self.assertRaises(Error):
            self._plugin()._ldap_connection_factory(self._factory_config())


class AttributeStoreHelpers(TestCase):
    def test_construct_query_value_returns_values(self):
        plugin = _build_api(_api_config())
        values = plugin._construct_query_value(
            {"attribute_names": ["uid"]}, _data({"uid": ["a", "b"]})
        )
        self.assertEqual(["a", "b"], values)

    def test_construct_query_value_missing_returns_none(self):
        plugin = _build_api(_api_config())
        self.assertIsNone(
            plugin._construct_query_value({"attribute_names": ["uid"]}, _data({}))
        )

    def test_populate_attributes_adds_eppn_scope(self):
        plugin = _build_api(_api_config())
        config = {
            "search_return_attributes": {"eppnAttr": ["eppn"]},
            "eppn_attr": "eppn",
            "eppn_scope": "example.org",
        }
        data = _data({})

        plugin._populate_attributes(config, {"attributes": {"eppnAttr": ["jdoe"]}}, data)

        self.assertEqual(["jdoe@example.org"], data.attributes["eppn"])

    def test_populate_attributes_skips_empty_values(self):
        plugin = _build_api(_api_config())
        config = {
            "search_return_attributes": {"cn": ["displayName"]},
            "eppn_attr": "eppn",
            "eppn_scope": "",
        }
        data = _data({})

        plugin._populate_attributes(config, {"attributes": {"cn": []}}, data)

        self.assertNotIn("displayName", data.attributes)

    def test_populate_attributes_accepts_string_mapping(self):
        plugin = _build_api(_api_config())
        config = {
            "search_return_attributes": {"cn": "displayName"},
            "eppn_attr": "eppn",
            "eppn_scope": "",
        }
        data = _data({})

        plugin._populate_attributes(config, {"attributes": {"cn": ["Found"]}}, data)

        self.assertEqual(["Found"], data.attributes["displayName"])

    def test_construct_query_value_name_id_missing_returns_none(self):
        plugin = _build_api(_api_config())

        result = plugin._construct_query_value(
            {"attribute_names": ["uid", "name_id"]}, _data({"uid": ["u1"]})
        )

        self.assertIsNone(result)


    def test_clear_attributes_keeps_exclusions(self):
        plugin = _build_api(_api_config())

        result = plugin._clear_attributes({"a": [1], "b": [2], "c": [3]}, exclusions=["b"])

        self.assertEqual({"b": [2]}, result)

    def test_filter_config_hides_sensitive_fields(self):
        plugin = _build_api(_api_config())

        filtered = plugin._filter_config(
            {
                "bind_password": "x",
                "api_auth_password": "s",
                "connection": object(),
                "other": "y",
            }
        )

        self.assertEqual("<hidden>", filtered["bind_password"])
        self.assertEqual("<hidden>", filtered["api_auth_password"])
        self.assertEqual("<hidden>", filtered["connection"])
        self.assertEqual("y", filtered["other"])


class AttributeStoreSearch(TestCase):
    def test_ldap_no_filter_values_skips_search(self):
        conn = MagicMock()
        plugin, _conn = _build_ldap(
            _ldap_config(
                ordered_identifier_candidates=[{"attribute_names": ["missing"]}]
            ),
            connection=conn,
        )

        record = plugin._search_via_ldap(plugin.config["default"], _data({}))

        self.assertEqual([], record)
        conn.search.assert_not_called()

    def test_ldap_membership_filter(self):
        conn = MagicMock()
        conn.search.return_value = "msg-1"
        conn.get_response.return_value = (
            [{"dn": "x", "attributes": {"cn": ["A"]}}],
            "status",
        )
        plugin, _conn = _build_ldap(
            _ldap_config(ldap_search_membership=True, account_registry_vo="vo-1"),
            connection=conn,
        )

        plugin._search_via_ldap(plugin.config["default"], _data({"uid": ["u1"]}))

        search_filter = conn.search.call_args.args[1]
        self.assertIn("groupNames=vo-1", search_filter)

    def test_ldap_store_exception_propagates(self):
        conn = MagicMock()
        conn.search.side_effect = Error("boom")
        plugin, _conn = _build_ldap(_ldap_config(), connection=conn)

        with self.assertRaises(Exception):
            plugin._search_via_ldap(plugin.config["default"], _data({"uid": ["u1"]}))

    def test_ldap_generic_exception_propagates(self):
        conn = MagicMock()
        conn.search.side_effect = ValueError("boom")
        plugin, _conn = _build_ldap(_ldap_config(), connection=conn)

        with self.assertRaises(Exception):
            plugin._search_via_ldap(plugin.config["default"], _data({"uid": ["u1"]}))

    @patch(f"{MODULE}.get_attrs", return_value=[])
    @patch(f"{MODULE}.get_user", return_value={"id": 1})
    def test_api_accepts_string_cuid(self, mock_get_user, _mock_attrs):
        plugin = _build_api(_api_config())

        result = plugin._search_via_api(plugin.config["default"], "cuid-str")

        self.assertEqual({"attributes": {}}, result)
        mock_get_user.assert_called_once()

    @patch(f"{MODULE}.get_user", side_effect=ValueError("boom"))
    def test_api_generic_exception_propagates(self, _mock_get_user):
        plugin = _build_api(_api_config())

        with self.assertRaises(Exception):
            plugin._search_via_api(plugin.config["default"], "cuid-str")
