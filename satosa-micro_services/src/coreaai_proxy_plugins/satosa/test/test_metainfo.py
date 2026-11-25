import os
import unittest

from satosa.context import Context
from satosa.internal import InternalData
from saml2.mdstore import MetadataStore
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.metainfo import MetaInfoIssuer
from coreaai_proxy_plugins.satosa.micro_services.metainfo import MetaInfoRequester

TEST_RESOURCE_BASE_PATH = os.path.join(os.path.dirname(__file__), "./test_resources")


class MetaInfoRequesterOidcTests(unittest.TestCase):
    def setUp(self):
        config = [
            {
                "requester": "APP-example_oidc_requester",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name", "contacts", "registration_info"],
                "issuer": "example_saml_issuer",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name", "contacts", "assurance_certifications"],
                "requester": "APP-example_oidc_requester",
                "issuer": "example_saml_issuer",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name"],
                "skip": "false"
            }
        ]
        self.plugin = MetaInfoRequester(config, name="MetaInfoRequester", base_url="https://proxy.example.org")
        self.plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        context.internal_data = {
            "requester_metadata": {
                "client_name": "Example OIDC Client",
                "policy_uri": "https://example.org",
                "contacts": [],
                "technical_contacts": [],
                "security_contacts": ["xyz"],
                "research_and_scholarship": "True",
                "sirtfi": "True",
                "shibmd_scopes": ["scope1", "scope2"]
            }
        }
        self.context = context

    def test_oidc_metadata_retrieved_all_fields(self):
        self.internal_data = InternalData(requester="APP-example_oidc_requester",
                                          auth_info={"issuer": "xyz_example_saml_issuer"})
        result = self.plugin.process(self.context, self.internal_data)
        expected_metadata = {
            "display_name": "Example OIDC Client",
            "privacy_statement": "https://example.org",
            "contacts": [{'contact_type': 'security', 'email_address': ['mailto:xyz'], 'given_name': ''}],
            "entity_categories": ['http://refeds.org/category/research-and-scholarship'],
            "supported_entity_categories": [],
            "assurance_certifications": ['https://refeds.org/sirtfi'],
            "registration_info": {},
            "issuer_shibmd_scopes": ["scope1", "scope2"]
        }
        assert result[1].data.get('metadata').get("APP-example_oidc_requester") == expected_metadata

    def test_oidc_metadata_retrieved_filtered_fields(self):
        self.internal_data = InternalData(requester="APP-example_oidc_requester",
                                          auth_info={"issuer": "example_saml_issuer"})
        result = self.plugin.process(self.context, self.internal_data)
        expected_metadata = {
            "display_name": "Example OIDC Client",
            "contacts": [{'contact_type': 'security', 'email_address': ['mailto:xyz'], 'given_name': ''}],
            "assurance_certifications": ['https://refeds.org/sirtfi']
        }
        assert result[1].data.get('metadata').get("APP-example_oidc_requester") == expected_metadata


class MetaInfoIssuerOidcTests(unittest.TestCase):
    def setUp(self):
        config = [
            {
                "metadata_field_names": ["display_name", "contacts", "registration_info"],
                "requester": "example_saml_requester",
                "skip": "false"
            },
            {
                "issuer": "APP-example_oidc_issuer",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name", "contacts", "assurance_certifications"],
                "requester": "example_saml_requester",
                "issuer": "APP-example_oidc_issuer",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name"],
                "skip": "false"
            }
        ]
        self.plugin = MetaInfoIssuer(config, name="MetaInfoIssuer", base_url="https://proxy.example.org")
        self.plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        context.internal_data = {
            "metadata_store": {
                "client_name": "Example OIDC Client",
                "policy_uri": "https://example.org",
                "contacts": [],
                "technical_contacts": [],
                "security_contacts": ["xyz"],
                "research_and_scholarship": "True",
                "sirtfi": "True",
                "shibmd_scopes": ["scope1", "scope2"]
            }
        }
        self.context = context

    def test_oidc_metadata_retrieved_all_fields(self):
        self.internal_data = InternalData(requester="xyz_example_saml_requester",
            auth_info={"issuer": "APP-example_oidc_issuer"})
        result = self.plugin.process(self.context, self.internal_data)
        expected_metadata = {
            "display_name": "Example OIDC Client",
            "privacy_statement": "https://example.org",
            "contacts": [{'contact_type': 'security', 'email_address': ['mailto:xyz'], 'given_name': ''}],
            "entity_categories": ['http://refeds.org/category/research-and-scholarship'],
            "supported_entity_categories": [],
            "assurance_certifications": ['https://refeds.org/sirtfi'],
            "registration_info": {},
            "issuer_shibmd_scopes": ["scope1", "scope2"]
        }
        assert result[1].data.get('metadata').get("APP-example_oidc_issuer") == expected_metadata

    def test_oidc_metadata_retrieved_filtered_fields(self):
        self.internal_data = InternalData(requester="example_saml_requester",
                                          auth_info={"issuer": "APP-example_oidc_issuer"})
        result = self.plugin.process(self.context, self.internal_data)
        expected_metadata = {
            "display_name": "Example OIDC Client",
            "contacts": [{'contact_type': 'security', 'email_address': ['mailto:xyz'], 'given_name': ''}],
            "assurance_certifications": ['https://refeds.org/sirtfi']
        }
        assert result[1].data.get('metadata').get("APP-example_oidc_issuer") == expected_metadata


class MetaInfoRequesterSamlTests(unittest.TestCase):
    def setUp(self):
        config = [
            {
                "requester": "example_saml_requester",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name", "contacts", "registration_info"],
                "issuer": "APP-example_oidc_issuer",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name", "contacts", "issuer_shibmd_scopes"],
                "requester": "example_saml_requester",
                "issuer": "APP-example_oidc_issuer",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name"],
                "skip": "false"
            }
        ]
        self.plugin = MetaInfoRequester(config, name="MetaInfoRequester", base_url="https://proxy.example.org")
        self.plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        metadata = MetadataStore(None, None)
        metadata.load('local', os.path.join(TEST_RESOURCE_BASE_PATH, "saml_test_requester_metadata.xml"))
        context.internal_data = {
            "metadata_store": metadata
        }
        self.context = context

    def test_saml_metadata_retrieved_all_fields(self):
        self.internal_data = InternalData(requester="example_saml_requester",
                                          auth_info={"issuer": "XYZ-example_oidc_issuer"})
        result = self.plugin.process(self.context, self.internal_data)
        expected_metadata = {
            "display_name": "Example SAML Client",
            "privacy_statement": "https://example.org",
            "contacts": [{'contact_type': 'technical', 'given_name': '', 'email_address': ['abc']}],
            "entity_categories": [],
            "supported_entity_categories": [],
            "assurance_certifications": [],
            "registration_info": {'registration_authority': None, 'registration_instant': None,
                                  'registration_policy': {}},
            "issuer_shibmd_scopes": [{'regexp': False, 'text': 'scope1'}, {'regexp': False, 'text': 'scope2'}]
        }
        assert result[1].data.get('metadata').get("example_saml_requester") == expected_metadata

    def test_saml_metadata_retrieved_filtered_fields(self):
        self.internal_data = InternalData(requester="example_saml_requester",
                                          auth_info={"issuer": "APP-example_oidc_issuer"})
        result = self.plugin.process(self.context, self.internal_data)
        expected_metadata = {
            "display_name": "Example SAML Client",
            "contacts": [{'contact_type': 'technical', 'given_name': '', 'email_address': ['abc']}],
            "issuer_shibmd_scopes": [{'regexp': False, 'text': 'scope1'}, {'regexp': False, 'text': 'scope2'}]
        }
        assert result[1].data.get('metadata').get("example_saml_requester") == expected_metadata


class MetaInfoIssuerSamlTests(unittest.TestCase):
    def setUp(self):
        config = [
            {
                "metadata_field_names": ["display_name", "contacts", "registration_info"],
                "requester": "APP-example_oidc_requester",
                "skip": "false"
            },
            {
                "issuer": "example_saml_issuer",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name", "contacts", "issuer_shibmd_scopes"],
                "requester": "APP-example_oidc_requester",
                "issuer": "example_saml_issuer",
                "skip": "false"
            },
            {
                "metadata_field_names": ["display_name"],
                "skip": "false"
            }
        ]
        self.plugin = MetaInfoIssuer(config, name="MetaInfoIssuer", base_url="https://proxy.example.org")
        self.plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()
        metadata = MetadataStore(None, None)
        metadata.load('local', os.path.join(TEST_RESOURCE_BASE_PATH, "saml_test_issuer_metadata.xml"))
        context.internal_data = {
            "metadata_store": metadata
        }
        self.context = context

    def test_saml_metadata_retrieved_all_fields(self):
        self.internal_data = InternalData(requester="XYZ-example_oidc_requester",
                                          auth_info={"issuer": "example_saml_issuer"})
        result = self.plugin.process(self.context, self.internal_data)
        expected_metadata = {
            "display_name": "Example SAML Client",
            "privacy_statement": "https://example.org",
            "contacts": [{'contact_type': 'technical', 'given_name': '', 'email_address': ['abc']}],
            "entity_categories": [],
            "supported_entity_categories": [],
            "assurance_certifications": [],
            "registration_info": {'registration_authority': None, 'registration_instant': None,
                                  'registration_policy': {}},
            "issuer_shibmd_scopes": [{'regexp': False, 'text': 'scope1'}, {'regexp': False, 'text': 'scope2'}]
        }
        assert result[1].data.get('metadata').get("example_saml_issuer") == expected_metadata

    def test_saml_metadata_retrieved_filtered_fields(self):
        self.internal_data = InternalData(requester="APP-example_oidc_requester",
                                          auth_info={"issuer": "example_saml_issuer"})
        result = self.plugin.process(self.context, self.internal_data)
        expected_metadata = {
            "display_name": "Example SAML Client",
            "contacts": [{'contact_type': 'technical', 'given_name': '', 'email_address': ['abc']}],
            "issuer_shibmd_scopes": [{'regexp': False, 'text': 'scope1'}, {'regexp': False, 'text': 'scope2'}]
        }
        assert result[1].data.get('metadata').get("example_saml_issuer") == expected_metadata


if __name__ == "__main__":
    unittest.main()
