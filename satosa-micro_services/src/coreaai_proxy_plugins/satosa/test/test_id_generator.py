import unittest

import yaml

from saml2.attribute_converter import ac_factory
from saml2.config import Config
from saml2.saml import NAMEID_FORMAT_PERSISTENT

from satosa.context import Context
from satosa.state import State
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData

from coreaai_proxy_plugins.satosa.micro_services.id_generator import IdGenerator
from coreaai_proxy_plugins.satosa.micro_services.id_generator import IdGeneratorError
from coreaai_proxy_plugins.satosa.micro_services.id_generator import SpecEvaluator
from coreaai_proxy_plugins.satosa.micro_services.id_generator import operators
from coreaai_proxy_plugins.satosa.micro_services.id_generator import search_attribute
from coreaai_proxy_plugins.satosa.micro_services.id_generator import search_element
from coreaai_proxy_plugins.satosa.micro_services.id_generator import search_element_issuer
from coreaai_proxy_plugins.satosa.micro_services.id_generator import (
    search_element_requester,
)
from coreaai_proxy_plugins.satosa.micro_services.id_generator import (
    search_element_authority,
)
from coreaai_proxy_plugins.satosa.micro_services.id_generator import (
    search_metadata_entity_categories,
)
from coreaai_proxy_plugins.satosa.micro_services.id_generator import (
    search_metadata_registration_authority_name,
)
from coreaai_proxy_plugins.satosa.micro_services.id_generator import searchers
from coreaai_proxy_plugins.satosa.micro_services.id_generator import serializers


ENTITY_CATEGORY_RNS = "http://refeds.org/category/research-and-scholarship"
REG_AUTH = "https://federation"


class IdGeneratorOldTests(unittest.TestCase):
    def setUp(self):
        config = yaml.safe_load(
            """
            id_attribute_name: epuid

            serialize: struct
            hash:
              algo: sha256
              salt: a-random-salt
            scope: some-scope

            identifiers_spec:
              - requirements:
                - type: truth
                  operands:
                  - type: attribute
                    name: mail
                selections:
                - type: element
                  name: issuer
                - type: attribute
                  name: eduPersonTargetedID
                - type: attribute
                  name: displayName
                - type: attribute
                  name: mail
                serialize: concat
                hash:
                  algo: sha512
                  salt: asecretsalt
                scope: someScope

              - requirements:
                - type: truth
                  operands:
                  - type: attribute
                    name: mail
                selections:
                - type: element
                  name: issuer
                - type: attribute
                  name: eduPersonTargetedID
                - type: attribute
                  name: displayName
                - type: attribute
                  name: mail
                serialize: concat
                hash:
                  algo: plain-text
                scope: ~ # no scope
            """
        )

        # as would be declared in internal_attributes.yaml
        internal_attributes = {
            "attributes": {
                "epuid": {"saml": ["eduPersonUniqueId", "epuid"]},
                "subject_id": {"saml": ["subject-id"]},
                "eptid": {"saml": ["eduPersonTargetedID"]},
                "eppn": {"saml": ["eduPersonPrincipalName"]},
                "assurance": {"saml": ["eduPersonAssurance", "epa"]},
                "common_name": {"saml": ["cn"]},
                "first_name": {"saml": ["givenName"]},
                "surname": {"saml": ["sn"]},
                "mail": {"saml": ["mail"]},
                "username": {"saml": ["displayName"]},
            }
        }

        plugin = IdGenerator(config, internal_attributes, "name", "baseUrl")
        plugin.next = lambda context, data: (context, data)

        context = Context()
        context.state = State()

        self.context = context
        self.plugin = plugin

    def test_process_simulate_old(self):
        issuer = ""
        internal_data = InternalData()
        internal_data.requester = "some-requester-entityid"
        internal_data.auth_info = AuthenticationInformation("", None, issuer)
        internal_data.attributes = {
            "eptid": ["edupersontargetedid_value"],
            "username": ["displayname_value"],
            "mail": ["mail_value@example.com"],
        }
        internal_data.subject_id = None
        internal_data.subject_type = None

        expected_ids = [
            "4a5868aaa47577e9bf7997243b3026525dcf20fa2f40b284d4a58614259628b21be971345c89a3b347192f825323c894e9c6e78e277564ef5aae6c205c3ea9e1@someScope",
            ''.join(
                v
                for values in [
                    [issuer],
                    internal_data.attributes.get("eptid", []),
                    internal_data.attributes.get("username", []),
                    internal_data.attributes.get("mail", []),
                ]
                for v in values
            ),
        ]

        self.plugin.process(self.context, internal_data)
        generated_ids = internal_data.attributes[self.plugin.id_attribute_name]
        self.assertEqual(generated_ids, expected_ids)

    def test_process_simulate_old_multiple_values(self):
        issuer = ""
        internal_data = InternalData()
        internal_data.requester = "some-requester-entityid"
        internal_data.auth_info = AuthenticationInformation("", None, issuer)
        internal_data.attributes = {
            "eptid": [
                "edupersontargetedid_value",
                "edupersontargetedid_value-2",
            ],
            "username": [
                "displayname_value",
                "displayname_value-2",
            ],
            "mail": ["mail_value@example.com"],
        }
        internal_data.subject_id = None
        internal_data.subject_type = None

        expected_ids = [
            "425298807bfd20fca8e5d42559f13e7ef4ede47279caa0017e09cd254d8c1a4f49122a862c1e1a2285a8750503d86d9bed8f6d31923d79b65020df4b3ba28653@someScope",
            ''.join(
                v
                for values in [
                    [issuer],
                    internal_data.attributes.get("eptid", []),
                    internal_data.attributes.get("username", []),
                    internal_data.attributes.get("mail", []),
                ]
                for v in values
            ),
        ]

        self.plugin.process(self.context, internal_data)
        generated_ids = internal_data.attributes[self.plugin.id_attribute_name]
        self.assertEqual(generated_ids, expected_ids)


class IdGeneratorTests(unittest.TestCase):
    def setUp(self):
        setUp(self)

    def test_process(self):
        issuer = "IDP_WITH_RNS_SUPPORT"
        internal_data = InternalData()
        internal_data.metadata = self.metadata
        internal_data.requester = "some-requester-entityid"
        internal_data.auth_info = AuthenticationInformation("", None, issuer)
        internal_data.attributes = {
            "epuid": ["some-epuid"],
            "subject_id": ["some-subject-id"],
            "eptid": ["some-eptid"],
            "eppn": ["some-eppn"],
            "assurance": ["edu-assurance"],
            "common_name": ["student-common-name"],
            "first_name": ["student-given-name"],
            "surname": ["student-surname"],
            "mail": ["student@institution.org"],
            "username": ["student-display-name"],
            "affiliation": ["employee", "member", "staff", "student"],
        }
        internal_data.subject_id = "foo"
        internal_data.subject_type = NAMEID_FORMAT_PERSISTENT

        expected_ids = [
            # req2: issuer+persistent_NameID|struct_obj|plain|scope
            '{"issuer":"' + issuer + '","name_id":"' + internal_data.subject_id + '"}',
            # req3: issuer+persistent_NameID|struct_obj|sha512|scope
            "2757c6886f754bbf8024945537492a297df407db254458b0ae449f4635265007f3f063abff798001f31de458df9f74661224c81f7a40e9c5a2eb5eda03a48099@some-scope",
            # req4: issuer+persistent_NameID|struct|sha512|scope
            "105c665cfe691910081426b390e6263e9546db7866609ae28563964fee5d62cb8fc702036fb8eb8b7aca6d10f35bdc12411b864801dde5f1c3bbe9f237d207d5@some-scope",
            # req5: issuer+persistent_NameID|concat|plain|no_scope
            issuer + internal_data.subject_id,
            # req6: issuer+subject-id|struct|sha512|no_scope
            "c5931dcdb3d331fedcf922706e0d93db367d5908aef422dfaa1bec8555b53ca18d4e4e7114db5104e9c13857a7023890836bb869726fa7506d90e79236cd91d1",
            # req8: issuer+eppn+eptid|struct|sha512|scope
            "e3a8d678ad9e0fea09f6f5b690b2a1a80d2ec330cc178e5f5a3ddc22d2678a242f960ec859404f0375c708491c72268bd6b5d0468951947f372dd7b3829ab39d@some-scope",
            # req9: issuer+eptid|struct|sha512|scope
            "9b1fa353056757b2375981a67f4d409fe50909ad21ea74bd7ee0fec25611e4ce9e2bd1299541260aa51752565e9ba7ca2579e525b3627f67fc9cdc08a15968e7@some-scope",
            # req10: issuer+eppn+mail+cn+givenName+sn+displayName|struct|sha512|scope
            "e1c779c905a5a2ba6dd245729f87d4a3e4ffa08652f0e064996a2e60b6c8b26b809a5d24d7a45a366152d3998efb2bfb1b8d111175c85b985ce087d665c81106@some-scope",
        ]

        self.plugin.process(self.context, internal_data)
        generated_ids = internal_data.attributes[self.plugin.id_attribute_name]
        self.assertListEqual(generated_ids, expected_ids)

    def test_process_multiple_values(self):
        issuer = "IDP_WITH_RNS_SUPPORT"
        internal_data = InternalData()
        internal_data.metadata = self.metadata
        internal_data.requester = "some-requester-entityid"
        internal_data.auth_info = AuthenticationInformation("", None, issuer)
        internal_data.attributes = {
            "epuid": ["some-epuid"],
            "eptid": [
                "some-eptid",
                "some-eptid-2",
                "some-eptid-3",
            ],
            "eppn": ["some-eppn"],
            "assurance": ["edu-assurance"],
            "common_name": ["student-common-name"],
            "first_name": ["student-given-name"],
            "surname": ["student-surname"],
            "mail": ["student@institution.org"],
            "username": ["student-display-name"],
            "affiliation": ["employee", "member", "staff", "student"],
        }

        expected_ids = [
            # req8: issuer+eppn+eptid|struct|sha512|scope
            "7408619f780846fc0810278869b031d2aba865f52648efe2b22ff4651c5326d8f7a401a3071da09f453669e42e176749ca2baa8af34fb111f64f1f6bb5966d1e@some-scope",
            # req9: issuer+eptid|struct|sha512|scope
            "fb8ac6bf6d79b2c356326b317e449d2d6165552942bedcebb068583d9d9f3677cba1e87e47188b27354705750ed87c2c4711de603c0a47ed0bfff75d414e09a1@some-scope",
            # req10: issuer+eppn+mail+cn+givenName+sn+displayName|struct|sha512|scope
            "e1c779c905a5a2ba6dd245729f87d4a3e4ffa08652f0e064996a2e60b6c8b26b809a5d24d7a45a366152d3998efb2bfb1b8d111175c85b985ce087d665c81106@some-scope",
        ]

        self.plugin.process(self.context, internal_data)
        generated_ids = internal_data.attributes[self.plugin.id_attribute_name]
        self.assertListEqual(generated_ids, expected_ids)

    def test_empty_result_when_no_selection(self):
        internal_data = InternalData()
        internal_data.requester = "some-requester-entityid"
        internal_data.auth_info = AuthenticationInformation(
            "", None, "IDP_WITH_RNS_SUPPORT"
        )
        internal_data.attributes = {
            "epuid": [],
            "subject_id": [],
            "eptid": [],
            "eppn": [],
            "assurance": [],
            "common_name": [],
            "first_name": [],
            "surname": [],
            "mail": [],
            "username": [],
            "affiliation": [],
        }

        self.plugin.process(self.context, internal_data)
        stored_attr_name = self.config["id_attribute_name"]
        self.assertListEqual(internal_data.attributes[stored_attr_name], [])


class IdGeneratorComboTests(unittest.TestCase):
    def test_process(self):
        config = yaml.safe_load(
            """
            hash:
              algo: plain-text
              salt: ignored-because-algo-is-plain-text

            scope: ~ # no scope
            id_attribute_name: epuid
            serialize: struct_obj_combo

            identifiers_spec:
              - comment: "req1: persistent_NameID+issuer"
                requirements:
                - type: truth
                  operands:
                  - type: element
                    name: name_id
                - type: eq
                  operands:
                  - type: element
                    name: name_id_format
                  - type: value
                    value: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
                selections:
                - type: element
                  name: name_id
                - type: element
                  name: issuer

              - comment: "req2: issuer+subject-id"
                requirements:
                - type: truth
                  operands:
                  - type: attribute
                    name: subject-id
                selections:
                - type: element
                  name: issuer
                - type: attribute
                  name: subject-id

              - comment: "req3: issuer+non_reassignable_eppn"
                requirements:
                - type: truth
                  operands:
                  - type: attribute
                    name: eduPersonPrincipalName
                - type: eq
                  operands:
                  - type: attribute
                    name: eduPersonAssurance
                  - type: value
                    value: https://refeds.org/assurance/ID/eppn-unique-no-reassign
                selections:
                - type: element
                  name: issuer
                - type: attribute
                  name: eduPersonPrincipalName

              - comment: "req4: issuer+eppn+eptid"
                requirements:
                - type: truth
                  operands:
                  - type: attribute
                    name: eduPersonPrincipalName
                - type: contains
                  operands:
                  - type: metadata
                    name: entity-category-support
                  - type: value
                    value: http://refeds.org/category/research-and-scholarship
                selections:
                - type: element
                  name: issuer
                - type: attribute
                  name: eduPersonPrincipalName
                - type: attribute
                  name: eduPersonTargetedID

              - comment: "req5: issuer+eptid"
                requirements:
                - type: truth
                  operands:
                  - type: attribute
                    name: eduPersonTargetedID
                selections:
                - type: element
                  name: issuer
                - type: attribute
                  name: eduPersonTargetedID
            """
        )

        # as would be declared in internal_attributes.yaml
        internal_attributes = {
            "attributes": {
                "epuid": {"saml": ["eduPersonUniqueId", "epuid"]},
                "subject_id": {"saml": ["subject-id"]},
                "eptid": {"saml": ["eduPersonTargetedID"]},
                "eppn": {"saml": ["eduPersonPrincipalName"]},
                "assurance": {"saml": ["eduPersonAssurance", "epa"]},
                "common_name": {"saml": ["cn"]},
                "first_name": {"saml": ["givenName"]},
                "surname": {"saml": ["sn"]},
                "mail": {"saml": ["mail"]},
                "username": {"saml": ["displayName"]},
            }
        }

        issuer = "IDP_WITH_RNS_SUPPORT"

        context = Context()
        context.state = State()

        internal_data = InternalData()
        internal_data.metadata = {
            "IDP_WITHOUT_RNS": {
                "supported_entity_categories": [],
                "entity_categories": [],
            },
            "IDP_WITH_RNS_SUPPORT": {
                "supported_entity_categories": [ENTITY_CATEGORY_RNS],
            },
            "IDP_WITH_RNS": {
                "entity_categories": [ENTITY_CATEGORY_RNS],
            },
            "IDP_REG_IN_FED": {
                "registration_info": {"registration_authority": REG_AUTH},
            },
        }

        name_id = "name-id-value"
        subject_id = "some-subject-id"
        eppn = "some-eppn"
        eptids = ["some-eptid", "some-eptid-2", "some-eptid-3"]

        internal_data.attributes = {
            "epuid": ["some-epuid"],
            "subject_id": [subject_id],
            "eptid": eptids,
            "eppn": [eppn],
            "assurance": ["edu-assurance"],
            "common_name": ["student-common-name"],
            "first_name": ["student-given-name"],
            "surname": ["student-surname"],
            "mail": ["student@institution.org"],
            "username": ["student-display-name"],
            "affiliation": ["employee", "member", "staff", "student"],
        }
        internal_data.auth_info = AuthenticationInformation("", None, issuer)
        internal_data.subject_id = name_id
        internal_data.subject_type = NAMEID_FORMAT_PERSISTENT

        plugin = IdGenerator(config, internal_attributes, "name", "baseUrl")
        plugin.next = lambda context, data: (context, data)

        expected_ids = (
            [
                # req1: name_id+issuer
                f'{{"name_id":"{name_id}","issuer":"{issuer}"}}',
                # req2: issuer+subject-id
                f'{{"issuer":"{issuer}","subject-id":"{subject_id}"}}',
            ] + [
                # req4: issuer+eppn+eptid
                f'{{"issuer":"{issuer}","eduPersonPrincipalName":"{eppn}","eduPersonTargetedID":"{eptid}"}}'
                for eptid in eptids
            ] + [
                # req5: issuer+eptid
                f'{{"issuer":"{issuer}","eduPersonTargetedID":"{eptid}"}}'
                for eptid in eptids
            ]
        )

        new_ctx, new_data = plugin.process(context, internal_data)
        generated_ids = new_data.attributes[plugin.id_attribute_name]
        self.assertListEqual(generated_ids, expected_ids)


class SpecEvaluatorTests(unittest.TestCase):
    def setUp(self):
        setUp(self)
        self.plugin = SpecEvaluator(
            self.searchers_adapted, operators, serializers, self.issuer
        )

    def test_evaluate_operation(self):
        operation_spec = {
            "type": "truth",
            "operands": [{"type": "attribute", "name": "mail"}],
        }
        expected = {
            "type": "truth",
            "operands": [
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                }
            ],
            "value": True,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_identifiers(self):
        identifier_spec = {
            "requirements": [
                {"type": "truth", "operands": [{"type": "attribute", "name": "mail"}]}
            ],
            "selections": [
                {"type": "element", "name": "issuer"},
                {"type": "attribute", "name": "eduPersonTargetedID"},
                {"type": "attribute", "name": "displayName"},
                {"type": "attribute", "name": "mail"},
            ],
            "serialize": "concat",
            "hash": {"algo": "sha512", "salt": "asecretsalt"},
            "scope": "someScope",
        }
        result = self.plugin.evaluate_identifiers(identifier_spec)
        expected = {
            "requirements": [
                {
                    "type": "truth",
                    "operands": [
                        {
                            "type": "attribute",
                            "name": "mail",
                            "value": ["student@institution.org"],
                        }
                    ],
                    "value": True,
                }
            ],
            "selections": [
                {
                    "type": "element",
                    "name": "issuer",
                    "value": "IDP_WITH_RNS_SUPPORT",
                },
                {
                    "type": "attribute",
                    "name": "eduPersonTargetedID",
                    "value": ["some-eptid"],
                },
                {
                    "type": "attribute",
                    "name": "displayName",
                    "value": ["student-display-name"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "serialize": "concat",
            "hash": {"algo": "sha512", "salt": "asecretsalt"},
            "scope": "someScope",
            "satisfied": True,
            "values": ["b6366c6d15204e263f1621157d38779776b9346e76bab97d775b0116624cf7b4d1dd1fb976e896eaeffd4d221ce5591f16a7d7294225e17973641c966f240c8d@someScope"],
        }
        self.assertDictEqual(expected, result)


class SpecEvaluatorOperatorContains(unittest.TestCase):
    def setUp(self):
        setUp(self)
        self.plugin = SpecEvaluator(
            self.searchers_adapted, operators, serializers, self.issuer
        )

    def test_evaluate_operation_success(self):
        operation_spec = {
            "type": "contains",
            "operands": [
                {
                    "type": "value",
                    "value": [["student@institution.org"]],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                },
            ],
        }
        expected = {
            "type": "contains",
            "operands": [
                {
                    "type": "value",
                    "value": [["student@institution.org"]],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "value": True,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_operation_fail(self):
        operation_spec = {
            "type": "contains",
            "operands": [
                {
                    "type": "value",
                    "value": [["random data"]],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                },
            ],
        }
        expected = {
            "type": "contains",
            "operands": [
                {
                    "type": "value",
                    "value": [["random data"]],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "value": False,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_not_operation_success(self):
        operation_spec = {
            "type": "not-contains",
            "operands": [
                {
                    "type": "value",
                    "value": [["random data"]],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                },
            ],
        }
        expected = {
            "type": "not-contains",
            "operands": [
                {
                    "type": "value",
                    "value": [["random data"]],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "value": True,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_not_operation_fail(self):
        operation_spec = {
            "type": "not-contains",
            "operands": [
                {
                    "type": "value",
                    "value": [["student@institution.org"]],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                },
            ],
        }
        expected = {
            "type": "not-contains",
            "operands": [
                {
                    "type": "value",
                    "value": [["student@institution.org"]],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "value": False,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)


class SpecEvaluatorOperatorEq(unittest.TestCase):
    def setUp(self):
        setUp(self)
        self.plugin = SpecEvaluator(
            self.searchers_adapted, operators, serializers, self.issuer
        )

    def test_evaluate_operation_success(self):
        operation_spec = {
            "type": "eq",
            "operands": [
                {
                    "type": "value",
                    "value": ["student@institution.org"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                },
            ],
        }
        expected = {
            "type": "eq",
            "operands": [
                {
                    "type": "value",
                    "value": ["student@institution.org"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "value": True,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_operation_fail(self):
        operation_spec = {
            "type": "eq",
            "operands": [
                {
                    "type": "value",
                    "value": ["random data"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                },
            ],
        }
        expected = {
            "type": "eq",
            "operands": [
                {
                    "type": "value",
                    "value": ["random data"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "value": False,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_not_operation_success(self):
        operation_spec = {
            "type": "not-eq",
            "operands": [
                {
                    "type": "value",
                    "value": ["random data"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                },
            ],
        }
        expected = {
            "type": "not-eq",
            "operands": [
                {
                    "type": "value",
                    "value": ["random data"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "value": True,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_not_operation_fail(self):
        operation_spec = {
            "type": "not-eq",
            "operands": [
                {
                    "type": "value",
                    "value": ["student@institution.org"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                },
            ],
        }
        expected = {
            "type": "not-eq",
            "operands": [
                {
                    "type": "value",
                    "value": ["student@institution.org"],
                },
                {
                    "type": "attribute",
                    "name": "mail",
                    "value": ["student@institution.org"],
                },
            ],
            "value": False,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)


class SpecEvaluatorOperatorTruth(unittest.TestCase):
    def setUp(self):
        setUp(self)
        self.plugin = SpecEvaluator(
            self.searchers_adapted, operators, serializers, self.issuer
        )

    def test_evaluate_operation_success(self):
        operation_spec = {
            "type": "truth",
            "operands": [
                {
                    "type": "value",
                    "value": True,
                },
            ],
        }
        expected = {
            "type": "truth",
            "operands": [
                {
                    "type": "value",
                    "value": True,
                },
            ],
            "value": True,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_operation_fail(self):
        operation_spec = {
            "type": "truth",
            "operands": [
                {
                    "type": "value",
                    "value": False,
                },
            ],
        }
        expected = {
            "type": "truth",
            "operands": [
                {
                    "type": "value",
                    "value": False,
                },
            ],
            "value": False,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_not_operation_success(self):
        operation_spec = {
            "type": "not-truth",
            "operands": [
                {
                    "type": "value",
                    "value": False,
                },
            ],
        }
        expected = {
            "type": "not-truth",
            "operands": [
                {
                    "type": "value",
                    "value": False,
                },
            ],
            "value": True,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)

    def test_evaluate_not_operation_fail(self):
        operation_spec = {
            "type": "not-truth",
            "operands": [
                {
                    "type": "value",
                    "value": True,
                },
            ],
        }
        expected = {
            "type": "not-truth",
            "operands": [
                {
                    "type": "value",
                    "value": True,
                },
            ],
            "value": False,
        }
        result = self.plugin.evaluate_operation(operation_spec)
        self.assertDictEqual(expected, result)


class IdGeneratorErrorTests(unittest.TestCase):
    def setUp(self):
        setUp(self)

    def test_process_validator_false(self):
        config = self.config
        config["id_attribute_name"] = []

        with self.assertRaises(IdGeneratorError):
            plugin = IdGenerator(config, self.internal_attributes, "name", "baseUrl")
            plugin.next = lambda context, data: (context, data)


class IdGeneratorSearcherTests(unittest.TestCase):
    def setUp(self):
        setUp(self)

    def test_search_metadata_registration_authority_name(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation("", None, "IDP_REG_IN_FED")
        r = search_metadata_registration_authority_name(
            self.metadata, internal_data.auth_info.issuer
        )
        self.assertEqual(r, REG_AUTH)

    def test_search_metadata_entity_categories(self):
        r = search_metadata_entity_categories(self.metadata, 1)
        self.assertEqual(r, [])

    def test_search_metadata_registration_authority_name(self):
        r = search_metadata_registration_authority_name(self.metadata, 1)
        self.assertEqual(r, None)

    def test_search_element_issuer(self):
        internal_data = InternalData()
        internal_data.auth_info = AuthenticationInformation(
            "", None, "IDP_WITH_RNS_SUPPORT"
        )
        r = search_element_issuer(internal_data)
        self.assertEqual(r, "IDP_WITH_RNS_SUPPORT")

    def test_search_element_requester(self):
        internal_data = InternalData()
        internal_data.requester = "some-requester-entityid"
        r = search_element_requester(internal_data)
        self.assertEqual(r, "some-requester-entityid")

    def test_search_element_authority(self):
        internal_data = InternalData()
        r = search_element_authority(internal_data)
        self.assertEqual(r, None)

        internal_data.auth_info.authority = "some-entityid"
        r = search_element_authority(internal_data)
        self.assertEqual(r, "some-entityid")


def setUp(self):
    self.metadata = {
        "IDP_WITHOUT_RNS": {
            "supported_entity_categories": [],
            "entity_categories": [],
        },
        "IDP_WITH_RNS_SUPPORT": {
            "supported_entity_categories": [ENTITY_CATEGORY_RNS],
        },
        "IDP_WITH_RNS": {
            "entity_categories": [ENTITY_CATEGORY_RNS],
        },
        "IDP_REG_IN_FED": {
            "registration_info": {"registration_authority": REG_AUTH},
        },
    }

    config = yaml.safe_load(
        """
        hash:
          algo: sha512
          salt: a-random-salt

        scope: some-scope
        id_attribute_name: epuid
        serialize: struct

        identifiers_spec:
          - comment: "req1: issuer+eptid+displayName+mail|struct|blake2s|scope"
            requirements:  # aka operations
            - type: truth  # unary
              operands:
              - type: attribute
                name: mail
            - type: eq  # binary
              operands:
              - type: element
                name: name_id_format
              - type: value  # defines that the `value` key should be used as it is
                value: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
            - type: contains  # binary, but for this type the order matters
              operands:  # so, operands maintain their order
              - type: metadata
                name: entity-category-support
              - type: value
                value: http://refeds.org/category/research-and-scholarship
            - type: contains
              operands:
              - type: value
                value:  # a value that is a list
                - http://refeds.org/category/research-and-scholarship
                - http://refeds.org/category/research-and-scholarship-1
                - http://refeds.org/category/research-and-scholarship-22
              - type: attribute
                name: foobar
            - type: eq  # comparing two derived values
              operands:
              - type: element
                name: name_id
              - type: attribute
                name: epuid
            selections:
            - type: element
              name: issuer
            - type: attribute
              name: eduPersonTargetedID
            - type: attribute
              name: displayName
            - type: attribute
              name: mail
            serialize: struct
            hash:
              algo: blake2s
              salt: abcdef
            scope: the-scope

          - comment: "req2: persistent_NameID|struct_obj|plain"
            requirements:
            - type: truth
              operands:
              - type: element
                name: name_id
            - type: eq
              operands:
              - type: element
                name: name_id_format
              - type: value
                value: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
            selections:
            - type: element
              name: name_id
            - type: element
              name: issuer
            serialize: struct_obj
            hash:
              algo: plain-text
              salt: ignored
            scope: # no-scope

          - comment: "req3: persistent_NameID|struct_obj|sha512"
            requirements:
            - type: truth
              operands:
              - type: element
                name: name_id
            - type: eq
              operands:
              - type: element
                name: name_id_format
              - type: value
                value: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
            selections:
            - type: element
              name: issuer
            - type: element
              name: name_id
            serialize: struct_obj
            hash:
              algo: sha512
              salt: a-random-salt
            scope: some-scope

          - comment: "req4: persistent_NameID|struct|sha512"
            requirements:
            - type: truth
              operands:
              - type: element
                name: name_id
            - type: eq
              operands:
              - type: element
                name: name_id_format
              - type: value
                value: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
            selections:
            - type: element
              name: issuer
            - type: element
              name: name_id
            serialize: struct
            hash:
              algo: sha512
              salt: a-random-salt
            scope: some-scope

          - comment: "req5: persistent_NameID|concat|plain"
            requirements:
            - type: truth
              operands:
              - type: element
                name: name_id
            - type: eq
              operands:
              - type: element
                name: name_id_format
              - type: value
                value: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
            selections:
            - type: element
              name: issuer
            - type: element
              name: name_id
            serialize: concat
            hash:
              algo: plain-text
              salt: will_be_ignored
            scope: # no-scope

          - comment: "req6: issuer+subject-id|struct|sha512|no_scope"
            requirements:
            - type: truth
              operands:
              - type: attribute
                name: subject-id
            selections:
            - type: element
              name: issuer
            - type: attribute
              name: subject-id
            scope: ## clear scope

          - comment: "req7: issuer+non_reassignable_eppn|struct|sha512|scope"
            requirements:
            - type: truth
              operands:
              - type: attribute
                name: eduPersonPrincipalName
            - type: eq
              operands:
              - type: attribute
                name: eduPersonAssurance
              - type: value
                value: https://refeds.org/assurance/ID/eppn-unique-no-reassign
            selections:
            - type: element
              name: issuer
            - type: attribute
              name: eduPersonPrincipalName

          - comment: "req8: issuer+eppn+eptid|struct|sha512|scope"
            requirements:
            - type: truth
              operands:
              - type: attribute
                name: eduPersonPrincipalName
            - type: contains
              operands:
              - type: metadata
                name: entity-category-support
              - type: value
                value: http://refeds.org/category/research-and-scholarship
            selections:
            - type: element
              name: issuer
            - type: attribute
              name: eduPersonPrincipalName
            - type: attribute
              name: eduPersonTargetedID

          - comment: "req9: issuer+eptid|struct|sha512|scope"
            requirements:
            - type: truth
              operands:
              - type: attribute
                name: eduPersonTargetedID
            selections:
            - type: element
              name: issuer
            - type: attribute
              name: eduPersonTargetedID

          - comment: "req10: issuer+eppn+mail+cn+givenName+sn+displayName|struct|sha512|scope"
            requirements:
            - type: truth
              operands:
              - type: attribute
                name: eduPersonPrincipalName
            - type: truth
              operands:
              - type: attribute
                name: mail
            selections:
            - type: element
              name: issuer
            - type: attribute
              name: eduPersonPrincipalName
            - type: attribute
              name: mail
            - type: attribute
              name: cn
            - type: attribute
              name: givenName
            - type: attribute
              name: sn
            - type: attribute
              name: displayName
        """
    )

    # as would be declared in internal_attributes.yaml
    internal_attributes = {
        "attributes": {
            "epuid": {"saml": ["eduPersonUniqueId", "epuid"]},
            "subject_id": {"saml": ["subject-id"]},
            "eptid": {"saml": ["eduPersonTargetedID"]},
            "eppn": {"saml": ["eduPersonPrincipalName"]},
            "assurance": {"saml": ["eduPersonAssurance", "epa"]},
            "common_name": {"saml": ["cn"]},
            "first_name": {"saml": ["givenName"]},
            "surname": {"saml": ["sn"]},
            "mail": {"saml": ["mail"]},
            "username": {"saml": ["displayName"]},
        }
    }

    plugin = IdGenerator(config, internal_attributes, "name", "baseUrl")
    plugin.next = lambda context, data: (context, data)

    context = Context()
    context.state = State()
    self.context = context

    self.config = config
    self.internal_attributes = internal_attributes
    self.plugin = plugin

    internal_data = InternalData()
    internal_data.attributes = {
        "epuid": ["some-epuid"],
        "subject_id": ["some-subject-id"],
        "eptid": ["some-eptid"],
        "eppn": ["some-eppn"],
        "assurance": ["edu-assurance"],
        "common_name": ["student-common-name"],
        "first_name": ["student-given-name"],
        "surname": ["student-surname"],
        "mail": ["student@institution.org"],
        "username": ["student-display-name"],
        "affiliation": ["employee", "member", "staff", "student"],
    }
    internal_data.auth_info = AuthenticationInformation(
        "", None, "IDP_WITH_RNS_SUPPORT"
    )
    self.issuer = internal_data.auth_info.issuer

    internal_to_saml = {
        internal_name: protocols.get("saml", [])
        for internal_name, protocols in internal_attributes["attributes"].items()
    }

    saml_attributes = {
        attr_name: values
        for int_name, values in internal_data.attributes.items()
        for attr_name in internal_to_saml.get(int_name, [])
    }

    self.searchers_adapted = {
        **searchers,
        "attribute": lambda n: search_attribute(saml_attributes, n),
        "element": lambda n: search_element(internal_data, n),
    }


if __name__ == "__main__":
    unittest.main()
