import unittest
from unittest.mock import MagicMock, patch

from ldap3.core.exceptions import LDAPException
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.puhuri_userinfo import (
    PuhuriUserInfo,
    PuhuriUserInfoError,
)

MODULE = "coreaai_proxy_plugins.satosa.micro_services.puhuri_userinfo"


def _config(**overrides):
    config = {
        "userinfo_path": "userinfo",
        "ldap_url": "ldap://ldap.example.org",
        "bind_dn": "cn=bind",
        "bind_password": "pw",
        "search_base": "dc=example,dc=org",
        "search_return_attributes": {
            "voPersonApplicationUID;shadow": "x",
            "loginName": "y",
        },
    }
    config.update(overrides)
    return config


def _build(config=None, connection=None):
    conn = connection if connection is not None else MagicMock()
    with patch.object(PuhuriUserInfo, "_ldap_connection_factory", return_value=conn):
        plugin = PuhuriUserInfo(
            config if config is not None else _config(),
            name="PuhuriUserInfo",
            base_url="https://proxy.example.org",
        )
    return plugin, conn


def _context(authz="", path="userinfo/cuid-1"):
    context = Context()
    context.state = State()
    context.request_authorization = authz
    context._path = path
    return context


class PuhuriUserInfoEndpoints(unittest.TestCase):
    def test_registers_userinfo_route(self):
        plugin, _conn = _build(_config(userinfo_path="userinfo"))

        endpoints = plugin.register_endpoints()

        self.assertEqual(1, len(endpoints))
        regex, handler = endpoints[0]
        self.assertEqual("^userinfo/.*$", regex)
        self.assertEqual(plugin._handle_userinfo, handler)

    def test_no_userinfo_path_registers_nothing(self):
        plugin, _conn = _build(_config(userinfo_path=""))

        self.assertEqual([], plugin.register_endpoints())


class PuhuriUserInfoProcess(unittest.TestCase):
    def test_process_passes_through(self):
        plugin, _conn = _build()
        plugin.next = lambda context, data: (context, data)
        context = _context()
        data = InternalData()

        self.assertEqual((context, data), plugin.process(context, data))


class PuhuriUserInfoAuth(unittest.TestCase):
    def test_missing_token_returns_401(self):
        plugin, _conn = _build()

        result = plugin._handle_userinfo(_context(authz=""))

        self.assertIsInstance(result, Response)
        self.assertEqual("401 Unauthorized", result.status)

    def test_invalid_jwt_returns_401(self):
        plugin, _conn = _build()

        result = plugin._handle_userinfo(_context(authz="Bearer not-a-jwt"))

        self.assertEqual("401 Unauthorized", result.status)

    def test_malformed_authorization_returns_401(self):
        # A non-empty header without "Bearer " previously skipped the guard and
        # crashed on unpacking; it must return 401.
        plugin, _conn = _build()

        result = plugin._handle_userinfo(_context(authz="garbage"))

        self.assertIsInstance(result, Response)
        self.assertEqual("401 Unauthorized", result.status)


class PuhuriUserInfoLdapFactory(unittest.TestCase):
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
        plugin, _conn = _build()
        with self.assertRaises(PuhuriUserInfoError):
            plugin._ldap_connection_factory(self._factory_config(ldap_url=None))

    def test_missing_bind_dn_raises(self):
        plugin, _conn = _build()
        with self.assertRaises(PuhuriUserInfoError):
            plugin._ldap_connection_factory(self._factory_config(bind_dn=None))

    def test_missing_bind_password_raises(self):
        plugin, _conn = _build()
        with self.assertRaises(PuhuriUserInfoError):
            plugin._ldap_connection_factory(self._factory_config(bind_password=None))

    @patch(f"{MODULE}.ldap3")
    def test_creates_connection(self, mock_ldap3):
        mock_ldap3.Connection.return_value = "the-connection"
        plugin, _conn = _build()

        result = plugin._ldap_connection_factory(self._factory_config())

        self.assertEqual("the-connection", result)

    @patch(f"{MODULE}.ldap3")
    def test_ldap_exception_is_wrapped(self, mock_ldap3):
        mock_ldap3.Connection.side_effect = LDAPException("down")
        plugin, _conn = _build()

        with self.assertRaises(PuhuriUserInfoError):
            plugin._ldap_connection_factory(self._factory_config())


if __name__ == "__main__":
    unittest.main()
