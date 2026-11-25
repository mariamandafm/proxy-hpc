import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, Mock, ANY

import jwt
from requests import Session
from requests.structures import CaseInsensitiveDict
from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.helpers.iamapi import (
    LookupResult,
    LookupIdentity,
    Identity,
    IamApiRole,
    LookupParams,
    UpsertIdentityParams,
    RegisterAccountParams,
    AcceptedPolicy,
    AccountProfile,
    Account,
    current_context,
)
from coreaai_proxy_plugins.helpers.jwt import all_supported_algorithms
from coreaai_proxy_plugins.satosa.micro_services.iam_user_registration import (
    IamUserRegistration,
)


class TestIamUserRegistration(unittest.TestCase):
    def setUp(self):
        self.env_patcher = patch.dict(
            os.environ,
            {
                "SESSION_API_URL": "http://example.tld/sessions",
                "SESSION_API_KEY": "secretpassword",
            },
        )
        self.env_patcher.start()

        config = [
            {
                "skip": "false",
                "jwt_audience": "iam-api",
                "cuid_attribute": "subject-id",
                "iuid_attribute": "iuids",
                "iam_api_url": "http://foo.local/",
                "session_api_url": "http://foo.local/",
                "session_api_key": "foo",
                "api_request_timeout": 10,
                "claims_mapping": {
                    "given_name": "given_name",
                    "family_name": "family_name",
                    "email": "email",
                },
                "profile_mapping": {
                    "first_name": "given_name",
                    "last_name": "family_name",
                    "email": "email",
                },
                "policy_url": "https://policy-test.com",
                "policy_type": "policy_type",
                "role": "iam_proxy_service",
                "signing_keys": {
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "alg": "RS512",
                            "kid": "e64c6305-f1a1-4dfc-83bb-ba4e85a80ed2",
                            "d": "cDOoNLPsIEuvusTqE7a8yaQOm_iitgz3Uxbky3062NK9CylfvyFW-Ditau0SLU_ZLD0VM_QSkx-vteF4-8bEximkUxEl0kGU7J8XoXrdstBffn_TGYPyBTTCWKjBY7haL0veM_TI1u3SD8J9-OEJKiEOlIWiKkPO1zimNjHu-iFOvoIBAbPmv5pFF-B1IYB7KA35UHYiHk--p7T7DrWlyHd101aa9i8zcfkLMHlLXzznW0nc6IouB_nSELt4ttper4M2XBtMK24FgG6eMRllVZUle7ujKTh-hlb9y0mJTE9gZ4A7OE-5Z0z2os3mYb9kJNvD8fRgf-7cRCf2r8ytAQ",
                            "n": "359Htkp6vijHacBG8YSj1Y_RSgX7_PoSE96VyjBlMTD5u25wl9m-keg0p-Yhcrb8kUIBlKb_BUXI-JMJn9njV5wetdOVrlQuumyK_EZXKQ1Cs9EVWX-uW6c234lereNBolRDSzBsFlFE9zMDoXrvowf4Qh0HSz5YMtFSzUvYM-PTZCM9r1xJy4lUlUOlnCmtb7QhEN-KtEDW2jHxcRCnLBQ29JuvBjawC2eitosKhepLBFij3gdSQMyKvuIhX9cEktO8szsVTK_tfeKbVzzKv2Gy_qmMpqP5OmjNJskE9qKb2b-4z10LZBTk4JRTocwiyMET8eAidqUFbPScc_WPGQ",
                            "e": "AQAB",
                            "p": "9LnGP-KfPcHIOXABAsNqVkm1sspb6mK62pSAL30XivV_LDk-E3fNkOCguBLTCknvSsyLgxp6XJlo0e3iCL2VVMVJClTGOgvbSu603X_6tWIBSDjkIzAHTBrekA0T_U4GZ8JlOgibM5PzOMyO-fAMRF0ajcDSezbnsryq0695q_k",
                            "q": "6eyd-GQvKptIUkVwn4PSarFc9JzzEweSsuqyPf0nc5fZKvDUtfMeUR2N0Z0q60u6TShKn57F02vVhn0cZFGb-Zt344WoUnZGPKHYuvhnITbGI0BFHPGk1E6q3YUF88jF9SYl7o891Pye96KaLZwPztErfx34J6fBJtmkK9_qhCE",
                            "dp": "YmUnTpxhhkUZqe5cma3UXWk5gu9V0YFsu2GlwHI9OwPF5BQH32_12OBX_mqjK6naamqfVVEaDY0o1e8dSIJhPjosSdkX8lK-Evyy_7PrK26CMXWeVH-FD5ZmEekQNnJepO1GIfU_4ZcE3btxaRCY_gupF4GFn0DOG9E7pe0RsJE",
                            "dq": "LHaeXD1mvbmAWKr8SkW7NC58Vb6TcXWKC9oSgTfiTNV7IO9f7ynEBHUSpNoz8z-UrN_Qt2Bth89CaerT_7mHZT2I30VjhjEXDqVQ1dErgSOxK7gmqua_ht9hGPQU-o6aGgvjP-IYRaiy6q0Mk0jLtGsL0oC2z4rSavkJfJF2OSE",
                            "qi": "oDXcU-OA5SOTGLXrQpkIQcdvevFRnT0o39R26gGOINQf0R-q9fN97V-X_cjGkhH0uM_5TQs5KfCDV6ZFScqn6SQrufR3ISQu2VfQC_vl6eP4jgRP2yChw89Xv4pet9LlyE7Q2-biRxQri9B-fZUPJ0B_q_vPA9uxVauNoDarCNE",
                        }
                    ]
                },
                "terminate_flow_on_error": False,
                "error_url": "https://example.com/error",
                "token_lifetime_seconds": 20 * 60,
            }
        ]

        plugin = IamUserRegistration(
            config, name="name", base_url="https://example.com"
        )
        plugin.next = lambda context, data: (context, data)

        self.config: list[dict] = config
        self.plugin = plugin

    def tearDown(self):
        self.env_patcher.stop()

    @patch(
        "coreaai_proxy_plugins.satosa.micro_services.iam_user_registration.IamApiClient",
        autospec=True,
    )
    def test_process_method_success(self, MockClient):
        issuer_uid = "91d555ab-c146-4022-b830-04e69be8c4f6"
        cuid = "identity-a"
        iuid = "iuid-a"
        now = datetime.now()
        updated_at = now - timedelta(hours=1)
        created_at = updated_at - timedelta(hours=1)
        identity = LookupIdentity(
            cuid=cuid,
            iuids=[iuid],
            issuer_uid=issuer_uid,
            claims={"email": "someone@example.com"},
            matches=["iuid-a"],
            created_at=created_at,
            updated_at=updated_at,
        )
        mock_client = Mock()
        MockClient.return_value = mock_client
        mock_client.lookup.return_value = LookupResult(identities=[identity])
        mock_client.upsert_identity.return_value = Identity.parse_obj(identity.dict())
        mock_client.register_account.return_value = Account(
            account_uid="foo-account",
            cuids=[identity.cuid],
            profile=AccountProfile.parse_obj(
                {
                    "first_name": "John",
                    "last_name": "Doe",
                    "email": "someone@example.com",
                }
            ),
            accepted_policies=[
                AcceptedPolicy(
                    policy_url="http://example.com/acceptable_usage_policy",
                    policy_type="acceptable_usage_policy",
                ),
            ],
            updated_at=now,
            created_at=now,
        )

        context = Context()
        context.state = State()
        internal_data = InternalData(
            requester="the-requester",
            auth_info=AuthenticationInformation(issuer=issuer_uid),
            attributes={
                "iuids": [iuid],
                "subject-id": [cuid],
                "family_name": "Doe",
                "given_name": "John",
                "email": "someone@foo.com",
                "policy_aup": "http://example.com/acceptable_usage_policy",
                "policy_tou": "http://example.com/terms_of_use",
                "policy_privacy": "http://example.com/privacy_policy",
            },
        )

        result = self.plugin.process(context, internal_data)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, tuple)
        context, attributes = result
        self.assertIsInstance(context, Context)
        self.assertIsInstance(attributes, InternalData)

        mock_client.lookup.assert_called_once_with(
            LookupParams(
                iuids=[iuid],
                issuer_uid=issuer_uid,
                service_uid="the-requester",
            ),
            timeout=ANY,
        )

        mock_client.upsert_identity.assert_called_once_with(
            UpsertIdentityParams(
                iuids=[iuid],
                cuid=cuid,
                issuer_uid=issuer_uid,
                claims={
                    "family_name": "Doe",
                    "given_name": "John",
                    "email": "someone@foo.com",
                },
            ),
            timeout=ANY,
        )

        mock_client.register_account.assert_called_once_with(
            RegisterAccountParams.construct(
                account_uid=ANY,
                cuids=[cuid],
                profile={
                    "first_name": "John",
                    "last_name": "Doe",
                    "email": "someone@foo.com",
                },
                accepted_policies=[
                    AcceptedPolicy(
                        policy_url="http://example.com/acceptable_usage_policy",  # type: ignore
                        policy_type="acceptable_usage_policy",
                    ),
                    AcceptedPolicy(
                        policy_url="http://example.com/terms_of_use",  # type: ignore
                        policy_type="terms_of_use",
                    ),
                    AcceptedPolicy(
                        policy_url="http://example.com/privacy_policy",  # type: ignore
                        policy_type="privacy_policy",
                    ),
                ],
            ),
            timeout=ANY,
        )

        # Check token passed
        MockClient.assert_called()
        args, kwargs = MockClient.call_args
        self.assertIn("session", kwargs)
        session = kwargs["session"]
        self.assertIsInstance(session, Session)
        self.assertIsInstance(session.headers, CaseInsensitiveDict)
        self.assertIn("Authorization", session.headers)
        authorization = session.headers.get("Authorization", None)
        self.assertIsInstance(authorization, str)
        self.assertTrue(authorization.startswith("Bearer "))
        payload = jwt.decode(
            authorization.removeprefix("Bearer "),
            verify=False,
            options={"verify_signature": False},
            algorithms=list(all_supported_algorithms),  # type: ignore[arg-type],
        )

        self.assertIsInstance(payload, dict)
        self.assertIn("sub", payload)
        self.assertIn("jti", payload)
        self.assertIn("exp", payload)
        self.assertIn("iat", payload)
        actual_claims = IamApiRole.IAM_ACCOUNT_OWNER.claims()
        expect_claims = {
            "iam_role": "iam_account_owner",
        }
        self.assertDictEqual(expect_claims, actual_claims)
        # Assert payload contains iam related claims
        self.assertEqual(
            payload, payload | expect_claims, "JWT payload should contain iam claims"
        )

    @patch(
        "coreaai_proxy_plugins.satosa.micro_services.iam_user_registration.IamApiClient",
        autospec=True,
    )
    def test_process_method_updates_existing_account(self, MockClient):
        issuer_uid = "91d555ab-c146-4022-b830-04e69be8c4f6"
        cuid = "identity-a"
        iuid = "iuid-a"
        account_uid = "existing-account"
        now = datetime.now()
        updated_at = now - timedelta(hours=1)
        created_at = updated_at - timedelta(hours=1)

        # Create a lookup result that includes an existing account
        identity = LookupIdentity(
            cuid=cuid,
            iuids=[iuid],
            issuer_uid=issuer_uid,
            claims={"email": "someone@example.com"},
            matches=["iuid-a"],
            created_at=created_at,
            updated_at=updated_at,
        )

        # Include an account in the lookup result to trigger the update branch
        lookup_result = LookupResult(
            identities=[identity],
            accounts=[
                Account(
                    account_uid=account_uid,
                    cuids=[cuid],
                    created_at=created_at,
                    updated_at=updated_at,
                )
            ],
        )

        mock_client = Mock()
        MockClient.return_value = mock_client
        mock_client.lookup.return_value = lookup_result
        mock_client.upsert_identity.return_value = Identity.parse_obj(identity.dict())
        mock_client.patch_account_profile.return_value = Account(
            account_uid=account_uid,
            cuids=[identity.cuid],
            profile=AccountProfile.parse_obj(
                {
                    "first_name": "Jane",  # Updated name
                    "last_name": "Smith",  # Updated name
                    "email": "jane.smith@example.com",  # Updated email
                }
            ),
            updated_at=now,
            created_at=updated_at,
        )

        context = Context()
        context.state = State()
        internal_data = InternalData(
            requester="the-requester",
            auth_info=AuthenticationInformation(issuer=issuer_uid),
            attributes={
                "iuids": [iuid],
                "subject-id": [cuid],
                "family_name": "Smith",  # New value
                "given_name": "Jane",  # New value
                "email": "jane.smith@example.com",  # New value
                "policy_aup": "http://example.com/acceptable_usage_policy",
                "policy_tou": "http://example.com/terms_of_use",
                "policy_privacy": "http://example.com/privacy_policy",
            },
        )

        def next(satosa_ctx, data):
            ctx = current_context()
            self.assertIsNotNone(ctx)
            self.assertIsInstance(ctx.account_info, LookupResult)
            self.assertIsNotNone(ctx.account_info.identities)
            self.assertIsNotNone(ctx.account_info.accounts)
            self.assertEqual(len(ctx.account_info.identities), 1)
            self.assertEqual(ctx.account_info.identities[0].cuid, cuid)
            self.assertEqual(ctx.account_info.identities[0].matches, [iuid])
            self.assertEqual(len(ctx.account_info.accounts), 1)
            self.assertEqual(ctx.account_info.accounts[0].account_uid, account_uid)
            return satosa_ctx, data

        _next = self.plugin.next
        self.plugin.next = next
        result = self.plugin.process(context, internal_data)
        self.plugin.next = _next

        self.assertIsNotNone(result)
        self.assertIsInstance(result, tuple)
        context, attributes = result
        self.assertIsInstance(context, Context)
        self.assertIsInstance(attributes, InternalData)

        # Verify lookup was called
        mock_client.lookup.assert_called_once_with(
            LookupParams(
                iuids=[iuid],
                issuer_uid=issuer_uid,
                service_uid="the-requester",
            ),
            timeout=ANY,
        )

        # Verify upsert_identity was called
        mock_client.upsert_identity.assert_called_once_with(
            UpsertIdentityParams(
                iuids=[iuid],
                cuid=cuid,
                issuer_uid=issuer_uid,
                claims={
                    "family_name": "Smith",
                    "given_name": "Jane",
                    "email": "jane.smith@example.com",
                },
            ),
            timeout=ANY,
        )

        # Verify patch_account_profile was called (instead of register_account)
        mock_client.patch_account_profile.assert_called_once_with(
            account_uid,
            AccountProfile(
                first_name="Jane",
                last_name="Smith",
                email="jane.smith@example.com",
            ),
            timeout=ANY,
        )

        # Check token passed for patch operation
        MockClient.assert_called()
        args, kwargs = MockClient.call_args
        self.assertIn("session", kwargs)
        session = kwargs["session"]
        self.assertIsInstance(session, Session)
        self.assertIsInstance(session.headers, CaseInsensitiveDict)
        self.assertIn("Authorization", session.headers)
        authorization = session.headers.get("Authorization", None)
        self.assertIsInstance(authorization, str)
        self.assertTrue(authorization.startswith("Bearer "))
        payload = jwt.decode(
            authorization.removeprefix("Bearer "),
            verify=False,
            options={"verify_signature": False},
            algorithms=list(all_supported_algorithms),  # type: ignore[arg-type],
        )

        self.assertIsInstance(payload, dict)
        self.assertIn("sub", payload)
        self.assertIn("jti", payload)
        self.assertIn("exp", payload)
        self.assertIn("iat", payload)
        actual_claims = IamApiRole.IAM_ACCOUNT_OWNER.claims(account_uid=account_uid)
        expect_claims = {
            "iam_role": "iam_account_owner",
            "iam_account_uid": account_uid,
        }
        self.assertDictEqual(expect_claims, actual_claims)
        # Assert payload contains iam related claims
        self.assertEqual(
            payload,
            payload | expect_claims,
            "JWT payload should contain iam claims for account owner",
        )


if __name__ == "__main__":
    unittest.main()
