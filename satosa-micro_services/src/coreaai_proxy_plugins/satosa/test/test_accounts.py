import unittest
from unittest.mock import MagicMock, patch

from ldap3 import Connection as LDAPConnection
from ldap3.core.exceptions import LDAPException

from satosa.context import Context
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.helpers.config import ConfigError as ResolveConfigError
from coreaai_proxy_plugins.helpers.perun.rpc import RPCError
from coreaai_proxy_plugins.satosa.micro_services.accounts import (
    AccountExistsError,
    ConfigError as AccountsConfigError,
    CreateAccount,
    Error,
    LookupStrategy,
    _process_create_account,
    create_account,
    create_fetch_ext_source,
    get_account_by_iuids,
    get_ext_user_by_login_iuid,
    get_ldap_account_by_attribute,
    update_ext_user_attrs,
)


SP = "https://sp.example.org"
IDP = "https://idp.example.org"
ERROR_URL = "https://err.example.org/error"
MODULE = "coreaai_proxy_plugins.satosa.micro_services.accounts"


# --------------------------------------------------------------------------- #
# orchestration helpers
# --------------------------------------------------------------------------- #
class GetAccountByIuids(unittest.TestCase):
    @patch(f"{MODULE}.get_ext_user_by_uniq_attr")
    def test_returns_first_match(self, mock_lookup):
        mock_lookup.side_effect = [None, {"id": 7}]

        self.assertEqual(
            {"id": 7}, get_account_by_iuids(MagicMock(), "perun_iuids", ["i1", "i2"])
        )

    @patch(f"{MODULE}.get_ext_user_by_uniq_attr")
    def test_rpcerror_treated_as_missing(self, mock_lookup):
        mock_lookup.side_effect = RPCError({"name": "x"})

        self.assertIsNone(get_account_by_iuids(MagicMock(), "a", ["i1"]))

    @patch(f"{MODULE}.get_ext_user_by_uniq_attr")
    def test_returns_none_when_no_match(self, mock_lookup):
        mock_lookup.return_value = None

        self.assertIsNone(get_account_by_iuids(MagicMock(), "a", ["i1", "i2"]))


class CreateFetchExtSource(unittest.TestCase):
    @patch(f"{MODULE}.get_ext_source")
    def test_returns_existing_source(self, mock_get):
        mock_get.return_value = {"id": 1}

        self.assertEqual({"id": 1}, create_fetch_ext_source(MagicMock(), "src"))

    @patch(f"{MODULE}.create_ext_source")
    @patch(f"{MODULE}.get_ext_source")
    def test_creates_source_when_missing(self, mock_get, mock_create):
        mock_get.side_effect = RPCError({"name": "ExtSourceNotExistsException"})
        mock_create.return_value = {"id": 2}

        self.assertEqual({"id": 2}, create_fetch_ext_source(MagicMock(), "src"))

    @patch(f"{MODULE}.get_ext_source")
    def test_other_rpcerror_raises(self, mock_get):
        mock_get.side_effect = RPCError({"name": "SomethingElse"})

        with self.assertRaises(Error):
            create_fetch_ext_source(MagicMock(), "src")

    @patch(f"{MODULE}.get_ext_source")
    def test_generic_error_raises(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")

        with self.assertRaises(Error):
            create_fetch_ext_source(MagicMock(), "src")

    @patch(f"{MODULE}.create_ext_source")
    @patch(f"{MODULE}.get_ext_source")
    def test_create_failure_raises(self, mock_get, mock_create):
        mock_get.side_effect = RPCError({"name": "ExtSourceNotExistsException"})
        mock_create.side_effect = RuntimeError("boom")

        with self.assertRaises(Error):
            create_fetch_ext_source(MagicMock(), "src")


def _call_create_account(**overrides):
    kwargs = dict(
        client=MagicMock(),
        vo_id=1,
        first_name="F",
        last_name="L",
        email="e@example.org",
        cuid="given-cuid",
        ext_source_name="src",
        ext_user_login="i1",
        attr_perun_user_pref_email="ppe",
        attr_perun_user_cuid="puc",
        enable_extensions_activate_user=False,
        attr_perun_activate_user="pau",
        activate_user_value="ACTIVE",
    )
    kwargs.update(overrides)
    return create_account(**kwargs)


class CreateAccountHelper(unittest.TestCase):
    @patch(f"{MODULE}.get_user_attr")
    @patch(f"{MODULE}.set_membership_status")
    @patch(f"{MODULE}.create_member")
    @patch(f"{MODULE}.prepare_candidate")
    @patch(f"{MODULE}.create_fetch_ext_source")
    def test_with_cuid_skips_attr_fetch(
        self, mock_src, mock_prep, mock_member, mock_status, mock_userattr
    ):
        mock_src.return_value = {"id": 1}
        mock_member.return_value = {"id": 10, "userId": 20}

        result = _call_create_account(cuid="given-cuid")

        self.assertEqual("given-cuid", result["cuid"])
        mock_userattr.assert_not_called()

    @patch(f"{MODULE}.get_user_attr")
    @patch(f"{MODULE}.set_membership_status")
    @patch(f"{MODULE}.create_member")
    @patch(f"{MODULE}.prepare_candidate")
    @patch(f"{MODULE}.create_fetch_ext_source")
    def test_without_cuid_fetches_it(
        self, mock_src, mock_prep, mock_member, mock_status, mock_userattr
    ):
        mock_src.return_value = {"id": 1}
        mock_member.return_value = {"id": 10, "userId": 20}
        mock_userattr.return_value = {"value": "fetched-cuid"}

        result = _call_create_account(cuid=None)

        self.assertEqual("fetched-cuid", result["cuid"])
        mock_userattr.assert_called_once()

    @patch(f"{MODULE}.get_user_attr")
    @patch(f"{MODULE}.set_membership_status")
    @patch(f"{MODULE}.create_member")
    @patch(f"{MODULE}.prepare_candidate")
    @patch(f"{MODULE}.create_fetch_ext_source")
    def test_activate_user_adds_attribute(
        self, mock_src, mock_prep, mock_member, mock_status, mock_userattr
    ):
        mock_src.return_value = {"id": 1}
        mock_member.return_value = {"id": 10, "userId": 20}

        _call_create_account(enable_extensions_activate_user=True)

        user_attrs = mock_prep.call_args.kwargs["user_attrs"]
        self.assertEqual("ACTIVE", user_attrs["pau"])

    @patch(f"{MODULE}.prepare_candidate")
    @patch(f"{MODULE}.create_fetch_ext_source")
    def test_failure_raises_error(self, mock_src, mock_prep):
        mock_src.return_value = {"id": 1}
        mock_prep.side_effect = RuntimeError("boom")

        with self.assertRaises(Error):
            _call_create_account()


class GetExtUserByLoginIuid(unittest.TestCase):
    @patch(f"{MODULE}.get_ext_user_by_login")
    def test_returns_ext_user(self, mock_get):
        mock_get.return_value = {"id": 5}

        self.assertEqual({"id": 5}, get_ext_user_by_login_iuid(MagicMock(), "src", "i1"))

    @patch(f"{MODULE}.get_ext_user_by_login")
    def test_error_raises(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")

        with self.assertRaises(Error):
            get_ext_user_by_login_iuid(MagicMock(), "src", "i1")


class UpdateExtUserAttrs(unittest.TestCase):
    @patch(f"{MODULE}.set_ext_user_attrs")
    @patch(f"{MODULE}.get_ext_user_attr")
    def test_arraylist_keeps_list(self, mock_def, mock_set):
        mock_def.return_value = {"type": "java.util.ArrayList", "friendlyName": "iuids"}

        update_ext_user_attrs(MagicMock(), 5, {"perun_iuids": ["a", "b"]})

        attrs = mock_set.call_args.kwargs["attributes"]
        self.assertEqual(["a", "b"], attrs["perun_iuids"]["value"])

    @patch(f"{MODULE}.set_ext_user_attrs")
    @patch(f"{MODULE}.get_ext_user_attr")
    def test_affiliation_is_joined(self, mock_def, mock_set):
        mock_def.return_value = {"type": "java.lang.String", "friendlyName": "affiliation"}

        update_ext_user_attrs(MagicMock(), 5, {"perun_aff": ["a@x", "b@y"]})

        attrs = mock_set.call_args.kwargs["attributes"]
        self.assertEqual("a@x;b@y", attrs["perun_aff"]["value"])

    @patch(f"{MODULE}.set_ext_user_attrs")
    @patch(f"{MODULE}.get_ext_user_attr")
    def test_scalar_uses_first_value(self, mock_def, mock_set):
        mock_def.return_value = {"type": "java.lang.String", "friendlyName": "email"}

        update_ext_user_attrs(MagicMock(), 5, {"perun_email": ["e@x", "e2@x"]})

        attrs = mock_set.call_args.kwargs["attributes"]
        self.assertEqual("e@x", attrs["perun_email"]["value"])

    @patch(f"{MODULE}.get_ext_user_attr")
    def test_fetch_definition_error_raises(self, mock_def):
        mock_def.side_effect = RuntimeError("boom")

        with self.assertRaises(Error):
            update_ext_user_attrs(MagicMock(), 5, {"perun_email": ["e@x"]})

    @patch(f"{MODULE}.set_ext_user_attrs")
    @patch(f"{MODULE}.get_ext_user_attr")
    def test_set_error_raises(self, mock_def, mock_set):
        mock_def.return_value = {"type": "java.lang.String", "friendlyName": "email"}
        mock_set.side_effect = RuntimeError("boom")

        with self.assertRaises(Error):
            update_ext_user_attrs(MagicMock(), 5, {"perun_email": ["e@x"]})


class GetLdapAccountByAttribute(unittest.TestCase):
    def test_returns_response(self):
        client = MagicMock()
        client.search.return_value = "req-id"
        client.get_response.return_value = (["entry"], "status")

        result = get_ldap_account_by_attribute(client, "dc=x", "uid", ["i1", "i2"])

        self.assertEqual(["entry"], result)
        client.search.assert_called_once()

    def test_ldap_exception_raises_error(self):
        client = MagicMock()
        client.search.side_effect = LDAPException("boom")

        with self.assertRaises(Error):
            get_ldap_account_by_attribute(client, "dc=x", "uid", ["i1"])


# --------------------------------------------------------------------------- #
# dispatcher
# --------------------------------------------------------------------------- #
def _call_process(strategy, iuids=("i1",), **overrides):
    kwargs = dict(
        lookup_strategy=strategy,
        ldap_client=MagicMock(),
        ldap_search_base="dc=x",
        ldap_iuids_attribute="ldapuid",
        http_client=MagicMock(),
        vo_id=1,
        issuer="iss",
        email="e@example.org",
        first_name="F",
        last_name="L",
        epsa=["epsa"],
        iuids=list(iuids),
        cuid_preset=None,
        attr_perun_ues_epsa="pe",
        attr_perun_ues_iuids="pi",
        attr_perun_user_pref_email="ppe",
        attr_perun_user_cuid="puc",
        enable_extensions_activate_user=False,
        attr_perun_activate_user="pau",
        activate_user_value="ACTIVE",
    )
    kwargs.update(overrides)
    return _process_create_account(**kwargs)


class ProcessCreateAccountDispatch(unittest.TestCase):
    @patch(f"{MODULE}.get_account_by_iuids")
    def test_rpc_existing_account_raises(self, mock_lookup):
        mock_lookup.return_value = {"id": 1}

        with self.assertRaises(AccountExistsError):
            _call_process(LookupStrategy.RPC_API)

    @patch(f"{MODULE}.get_ldap_account_by_attribute")
    def test_ldap_existing_account_raises(self, mock_lookup):
        mock_lookup.return_value = ["entry"]

        with self.assertRaises(AccountExistsError):
            _call_process(LookupStrategy.LDAP_API)

    @patch(f"{MODULE}.update_ext_user_attrs")
    @patch(f"{MODULE}.get_ext_user_by_login_iuid")
    @patch(f"{MODULE}.create_account")
    @patch(f"{MODULE}.get_account_by_iuids")
    def test_creates_when_not_existing(
        self, mock_lookup, mock_create, mock_extuser, mock_update
    ):
        mock_lookup.return_value = None
        mock_create.return_value = {"cuid": "c1"}
        mock_extuser.return_value = {"id": 9}

        result = _call_process(LookupStrategy.RPC_API)

        self.assertEqual({"cuid": "c1"}, result)
        mock_update.assert_called_once()

    def test_unknown_strategy_raises_error(self):
        with self.assertRaises(Error):
            _call_process("bogus")


# --------------------------------------------------------------------------- #
# process
# --------------------------------------------------------------------------- #
def _entry(**overrides):
    entry = dict(
        lookup_strategy="ldap_api",
        vo_id=1,
        vo_name="my-vo",
        cuid_external_provision=False,
        attr_internal_groups="groups",
        attr_internal_first_name="first_name",
        attr_internal_last_name="last_name",
        attr_internal_email="email",
        attr_internal_epsa="epsa",
        attr_internal_iuids="iuids",
        attr_internal_cuid_preset="cuid_preset",
        attr_internal_cuid="cuid",
        attr_perun_ues_iuids="perun_iuids",
        attr_perun_ues_epsa="perun_epsa",
        attr_perun_user_pref_email="perun_email",
        attr_perun_user_cuid="perun_cuid",
        attr_ldap_iuids="ldap_iuids",
        attr_perun_activate_user="perun_activate",
        activate_user_value="ACTIVE",
        ldap_url="ldap://ldap.example.org",
        ldap_bind_dn="cn=bind",
        ldap_bind_password="pw",
        ldap_pool_size=1,
        ldap_pool_keepalive=1,
        ldap_search_base="dc=example,dc=org",
        api_base_url="https://api.example.org",
        api_auth_user="apiuser",
        api_auth_password="apipw",
        error_url=ERROR_URL,
    )
    entry.update(overrides)
    return entry


def _rpc_entry(**overrides):
    # An rpc_api entry carries no LDAP params.
    entry = _entry(lookup_strategy="rpc_api")
    for key in (
        "ldap_url",
        "ldap_bind_dn",
        "ldap_bind_password",
        "ldap_pool_size",
        "ldap_pool_keepalive",
        "ldap_search_base",
        "attr_ldap_iuids",
    ):
        entry.pop(key, None)
    entry.update(overrides)
    return entry


def _full_attrs():
    return {
        "email": ["u@example.org"],
        "first_name": ["First"],
        "last_name": ["Last"],
        "iuids": ["iuid-1"],
        "epsa": ["epsa-1"],
        "cuid_preset": ["preset-cuid"],
    }


def _build_plugin(entries):
    with patch(f"{MODULE}.LDAPConnection") as conn_cls:
        conn_cls.return_value = MagicMock(spec=LDAPConnection)
        plugin = CreateAccount(entries, "", "")
    plugin.next = lambda context, data: (context, data)
    return plugin


def _context():
    context = Context()
    context.state = State()
    return context


def _data(attributes=None):
    return InternalData(
        auth_info=AuthenticationInformation(issuer=IDP),
        requester=SP,
        attributes=_full_attrs() if attributes is None else attributes,
    )


class CreateAccountProcess(unittest.TestCase):
    def test_skip_passes_through(self):
        plugin = _build_plugin([_entry(skip=True)])
        data = _data()

        _context_out, data_out = plugin.process(_context(), data)

        self.assertIs(data, data_out)
        self.assertNotIn("cuid", data.attributes)

    def test_empty_config_raises(self):
        with self.assertRaises(AccountsConfigError):
            CreateAccount([], "", "")

    def test_invalid_entry_raises_config_error(self):
        entry = _entry()
        del entry["vo_id"]  # required field
        with patch(f"{MODULE}.LDAPConnection") as conn_cls:
            conn_cls.return_value = MagicMock(spec=LDAPConnection)
            with self.assertRaises(AccountsConfigError):
                CreateAccount([entry], "", "")

    def test_ldap_connection_failure_raises_config_error(self):
        with patch(f"{MODULE}.LDAPConnection", side_effect=LDAPException("down")):
            with self.assertRaises(AccountsConfigError):
                CreateAccount([_entry()], "", "")

    def test_rpc_only_config_constructs(self):
        # An rpc_api-only config (no LDAP params) constructs: ldap_client is None
        # and the ldap_* fields are optional.
        plugin = _build_plugin([_rpc_entry()])

        self.assertIsInstance(plugin, CreateAccount)

    @patch(f"{MODULE}._process_create_account")
    def test_rpc_only_config_processes(self, mock_process):
        mock_process.return_value = {"cuid": "new-cuid"}
        plugin = _build_plugin([_rpc_entry()])
        data = _data()

        plugin.process(_context(), data)

        self.assertEqual(["new-cuid"], data.attributes["cuid"])
        _strategy, ldap_client, *_rest = mock_process.call_args.args
        self.assertIsNone(ldap_client)

    def test_no_fallback_raises_config_error(self):
        plugin = _build_plugin([_entry(requester=SP)])
        data = _data()

        with self.assertRaises(ResolveConfigError):
            plugin.process(_context(), data)

    @patch(f"{MODULE}._process_create_account")
    def test_missing_required_attribute_passes_through(self, mock_process):
        plugin = _build_plugin([_entry()])
        attrs = _full_attrs()
        del attrs["email"]
        data = _data(attrs)

        plugin.process(_context(), data)

        mock_process.assert_not_called()
        self.assertNotIn("cuid", data.attributes)

    @patch(f"{MODULE}._process_create_account")
    def test_external_provision_without_cuid_redirects(self, mock_process):
        plugin = _build_plugin([_entry(cuid_external_provision=True)])
        attrs = _full_attrs()
        del attrs["cuid_preset"]
        data = _data(attrs)

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(ERROR_URL, result.message)
        mock_process.assert_not_called()

    @patch(f"{MODULE}._process_create_account")
    def test_account_exists_passes_through(self, mock_process):
        mock_process.side_effect = AccountExistsError({"message": "exists"})
        plugin = _build_plugin([_entry()])
        data = _data()

        _context_out, data_out = plugin.process(_context(), data)

        self.assertIs(data, data_out)
        self.assertNotIn("cuid", data.attributes)

    @patch(f"{MODULE}._process_create_account")
    def test_error_redirects(self, mock_process):
        mock_process.side_effect = Error({"message": "boom"})
        plugin = _build_plugin([_entry()])
        data = _data()

        result = plugin.process(_context(), data)

        self.assertIsInstance(result, Redirect)
        self.assertEqual(ERROR_URL, result.message)

    @patch(f"{MODULE}._process_create_account")
    def test_success_sets_cuid_and_groups(self, mock_process):
        mock_process.return_value = {"cuid": "new-cuid"}
        plugin = _build_plugin([_entry()])
        data = _data()

        plugin.process(_context(), data)

        self.assertEqual(["new-cuid"], data.attributes["cuid"])
        self.assertEqual(["my-vo"], data.attributes["groups"])


if __name__ == "__main__":
    unittest.main()
