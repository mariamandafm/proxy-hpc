import json
import re
import unittest

from satosa.context import Context
from satosa.response import Response

from coreaai_proxy_plugins.satosa.micro_services.healthcheck import HealthCheck


class HealthCheckTests(unittest.TestCase):
    def setUp(self):
        self.plugin = HealthCheck({}, {}, "", "")

    def test_register_endpoints_exposes_healthcheck(self):
        endpoints = self.plugin.register_endpoints()

        self.assertEqual(1, len(endpoints))
        regex, _handler = endpoints[0]
        self.assertEqual("^healthcheck$", regex)

    def test_endpoint_regex_is_anchored(self):
        regex, _handler = self.plugin.register_endpoints()[0]

        self.assertTrue(re.match(regex, "healthcheck"))
        self.assertIsNone(re.match(regex, "xhealthcheck"))
        self.assertIsNone(re.match(regex, "healthcheckx"))

    def test_handler_returns_ok_status(self):
        _regex, handler = self.plugin.register_endpoints()[0]

        response = handler(Context())

        self.assertIsInstance(response, Response)
        self.assertEqual({"status": "ok"}, json.loads(response.message))


if __name__ == "__main__":
    unittest.main()
