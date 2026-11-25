import unittest
import uuid
from unittest.mock import patch, Mock
from urllib.parse import urlencode

import requests
from requests.sessions import Session

from coreaai_proxy_plugins.helpers.iamapi import IamApiClient, IamApiConfig, LookupParams


class TestIamApiClient(unittest.TestCase):
    def setUp(self):
        token = uuid.uuid4()
        session = Session()
        session.headers = {"Authorization": f"Bearer {token}"}
        config = IamApiConfig.parse_obj(
            {
                "base_url": "http://iamapi.org/",
            }
        )
        self.client = IamApiClient(config, session=session)
        self.expect_token = str(token)

    @patch("requests.sessions.Session.send")
    def test_lookup(self, mock_send: Mock):
        mock_response = Mock()
        mock_response.status_code = 200
        result_json = {
            "identities": [
                {
                    "cuid": "11f91eaa-8b5b-4246-94db-34e35485330c",
                    "issuer_uid": "91d555ab-c146-4022-b830-04e69be8c4f6",
                    "account_uid": None,
                    "iuids": [
                        "8f6bee7b-9497-4a3f-a04e-11a7f93feccc",
                        "e8a081b6-3312-4d26-8cd2-8b4409510fea",
                    ],
                    "matches": [
                        "8f6bee7b-9497-4a3f-a04e-11a7f93feccc",
                        "e8a081b6-3312-4d26-8cd2-8b4409510fea",
                    ],
                    "claims": {
                        "first_name": "John",
                        "last_name": "Doe",
                        "email": "john.doe@test.com",
                        "age": 30,
                    },
                    "created_at": "2024-07-24T06:48:22.355239+00:00",
                    "updated_at": "2024-07-24T06:48:22.355239+00:00",
                }
            ],
            "accounts": [
                {
                    "account_uid": "johndoe",
                    "cuids": ["11f91eaa-8b5b-4246-94db-34e35485330c"],
                    "created_at": "2024-07-24T06:48:22.355239+00:00",
                    "updated_at": "2024-07-24T06:48:22.355239+00:00",
                }
            ],
            "unresolved": None,
            "mfa_factors": None,
        }
        mock_response.json.return_value = {"result": result_json}
        mock_send.return_value = mock_response

        lookup_input = LookupParams(
            iuids=[
                "8f6bee7b-9497-4a3f-a04e-11a7f93feccc",
                "e8a081b6-3312-4d26-8cd2-8b4409510fea",
            ],
            service_uid="some-service",
            issuer_uid="91d555ab-c146-4022-b830-04e69be8c4f6",
        )
        result = self.client.lookup(lookup_input, timeout=42)

        self.assertIsNotNone(result)
        self.assertIsNotNone(result.identities, "no identities found")
        self.assertEqual(1, len(result.identities))
        mock_send.assert_called_once()
        call_args = mock_send.call_args_list[0]
        (actual_request,) = call_args[0]
        send_kwargs = call_args[1]
        self.assertIsInstance(actual_request, requests.models.PreparedRequest)
        self.assertEqual(
            actual_request.url,
            f"http://iamapi.org/api/v0/lookup?{urlencode(lookup_input.dict(), doseq=True)}",
        )
        self.assertEqual(actual_request.method, "GET")
        self.assertEqual(actual_request.body, None)
        self.assertEqual(
            actual_request.headers,
            {
                "Authorization": f"Bearer {self.expect_token}",
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(send_kwargs["timeout"], 42)


if __name__ == "__main__":
    unittest.main()
