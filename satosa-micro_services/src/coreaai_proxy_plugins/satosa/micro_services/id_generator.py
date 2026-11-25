import hashlib
import json
import logging
import operator
from collections import OrderedDict
from itertools import chain as chain_iterable
from itertools import product
from typing import Iterable
from typing import Mapping

from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class IdGeneratorError(SATOSAError):
    """Generic error."""


class IdGenerator(ResponseMicroService):
    """
    Generate identifiers from the given spec and store them in the specified attribute.

    Example configuration:
    ```
    id_attribute_name: identifiers

    serialize: struct
    scope: some-scope
    hash:
      algo: sha512
      salt: a-random-salt

    identifiers_spec:

      - requirements:  # aka operations
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
            type: element
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
        serialize: struct

      - requirements:
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
        - type: attribute
          name: eduPersonPrincipalName
        - type: attribute
          name: eduPersonTargetedID

      # If the IdP is registered by surfconext and the ePPN
      # is released, then use the ePPN
      - requirements:
        - type: truth
          operands:
          - type: attribute
            name: eduPersonPrincipalName
        - type: contains
          operands:
          - type: metadata
            name: registration-authority-name
          - type: value
            value: http://www.surfconext.nl/
        selections:
        - type: attribute
          name: eduPersonPrincipalName
    ```
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.internal_to_saml = {
            internal_name: protocols.get("saml", [])
            for internal_name, protocols in internal_attributes["attributes"].items()
        }

        identifiers_is_a_list_with_at_least_one_item = (
            not isinstance(config.get("identifiers_spec"), str)
            and isinstance(config.get("identifiers_spec"), Iterable)
            and config.get("identifiers_spec")
        )

        each_identifier_spec_is_a_mapping = (
            identifiers_is_a_list_with_at_least_one_item
            and all(isinstance(spec, Mapping) for spec in config["identifiers_spec"])
        )
        identifier_has_a_list_of_requirements = (
            each_identifier_spec_is_a_mapping
            and all(
                not isinstance(spec.get("requirements"), str)
                and isinstance(spec.get("requirements"), Iterable)
                for spec in config["identifiers_spec"]
            )
        )
        identifier_has_a_list_of_selections = each_identifier_spec_is_a_mapping and all(
            not isinstance(spec.get("selections"), str)
            and isinstance(spec.get("selections"), Iterable)
            and spec.get("selections")
            for spec in config["identifiers_spec"]
        )

        requirement_is_an_operation_mapping = (
            identifier_has_a_list_of_requirements
            and all(
                isinstance(operation, Mapping)
                for spec in config["identifiers_spec"]
                for operation in spec["requirements"]
            )
        )

        operations_have_a_supported_type = requirement_is_an_operation_mapping and all(
            isinstance(operation.get("type"), str)
            and operation["type"] in operators.keys()
            for spec in config["identifiers_spec"]
            for operation in spec["requirements"]
        )
        operations_have_a_list_of_operands = (
            requirement_is_an_operation_mapping
            and all(
                not isinstance(operation.get("operands"), str)
                and isinstance(operation.get("operands"), Iterable)
                for spec in config["identifiers_spec"]
                for operation in spec["requirements"]
            )
        )

        operands_are_entity_mappings = operations_have_a_list_of_operands and all(
            isinstance(entity, Mapping)
            for spec in config["identifiers_spec"]
            for operation in spec["requirements"]
            for entity in operation["operands"]
        )

        selections_are_entity_mappings = identifier_has_a_list_of_selections and all(
            isinstance(selection, Mapping)
            for spec in config["identifiers_spec"]
            for selection in spec["selections"]
        )

        entities_have_a_suppported_type = (
            selections_are_entity_mappings
            and operands_are_entity_mappings
            and all(
                isinstance(entity.get("type"), str)
                and entity["type"] in searchers.keys()
                for spec in config["identifiers_spec"]
                for operation in spec["requirements"]
                for entity in chain_iterable(operation["operands"], spec["selections"])
            )
        )
        entities_have_other_properties_supported = (
            entities_have_a_suppported_type
            and all(
                {
                    "attribute": lambda s: isinstance(s["name"], str),
                    "element": lambda s: isinstance(s["name"], str),
                    "metadata": lambda s: isinstance(s["name"], str),
                    "value": lambda s: "value" in s.keys(),
                }.get(entity["type"])(entity)
                and {
                    "attribute": True,
                    "element": entity.get("name") in searchers_element.keys(),
                    "metadata": entity.get("name") in searchers_metadata.keys(),
                    "value": True,
                }.get(entity["type"])
                for spec in config["identifiers_spec"]
                for operation in spec["requirements"]
                for entity in chain_iterable(operation["operands"], spec["selections"])
            )
        )

        id_attribute_name_is_a_string = isinstance(config.get("id_attribute_name"), str)

        serialize_is_set_globally_or_for_every_spec_as_a_string = isinstance(
            config.get("serialize"), str
        ) or (
            each_identifier_spec_is_a_mapping
            and all(
                isinstance(spec.get("serialize"), str)
                for spec in config["identifiers_spec"]
            )
        )
        serialize_is_supported = (
            serialize_is_set_globally_or_for_every_spec_as_a_string
            and all(
                spec["serialize"] in serializers.keys()
                for spec in [config, *config["identifiers_spec"]]
                if spec.get("serialize")
            )
        )

        scope_is_a_string = isinstance(config.get("scope"), str) or (
            each_identifier_spec_is_a_mapping
            and all(
                isinstance(spec["scope"], str)
                for spec in config["identifiers_spec"]
                if spec.get("scope")
            )
        )

        hash_is_set_globally_or_for_every_spec_as_a_mapping = isinstance(
            config.get("hash"), Mapping
        ) or (
            each_identifier_spec_is_a_mapping
            and all(
                isinstance(spec.get("hash"), Mapping)
                for spec in config["identifiers_spec"]
            )
        )
        hash_salt_is_always_set = (
            hash_is_set_globally_or_for_every_spec_as_a_mapping
            and all(
                isinstance(spec.get("salt"), str)
                for spec in [config, *config["identifiers_spec"]]
                if spec.get("salt")
            )
        )
        hash_algo_is_supported = (
            hash_is_set_globally_or_for_every_spec_as_a_mapping
            and all(
                spec["hash"]["algo"] in chain_iterable(
                    hashlib.algorithms_guaranteed, ["plain-text"]
                )
                for spec in [config, *config["identifiers_spec"]]
                if spec.get("hash", {}).get("algo")
            )
        )

        validators = {
            "identifiers_spec is a list with at least one item": (
                identifiers_is_a_list_with_at_least_one_item
            ),
            "each identifier is a mapping": each_identifier_spec_is_a_mapping,
            "identifier has a list of requirements": (
                identifier_has_a_list_of_requirements
            ),
            "identifier has a list of selections": identifier_has_a_list_of_selections,
            "requirement is an operation mapping": requirement_is_an_operation_mapping,
            "operations have a supported type": operations_have_a_supported_type,
            "operations have a list of operands": operations_have_a_list_of_operands,
            "operands are entity mappings": operands_are_entity_mappings,
            "selections are entity mappings": selections_are_entity_mappings,
            "entities have a suppported type": entities_have_a_suppported_type,
            "entities have other properties supported": (
                entities_have_other_properties_supported
            ),
            "id_attribute_name is a string": id_attribute_name_is_a_string,
            "serialize is set globally or for every spec as a string": (
                serialize_is_set_globally_or_for_every_spec_as_a_string
            ),
            "serialize is supported": serialize_is_supported,
            "scope is a string": scope_is_a_string,
            "hash is set globally or for every spec as a mapping": (
                hash_is_set_globally_or_for_every_spec_as_a_mapping
            ),
            "hash salt is always set": hash_salt_is_always_set,
            "hash algo is supported": hash_algo_is_supported,
        }
        if not all(validators.values()):
            error_context = {
                "message": " ".join(
                    [
                        "The configuration for this plugin is not valid.",
                        "Make sure that the following rules are met:",
                        ", ".join(validators.keys()),
                    ]
                ),
                "validators": validators,
                "config": config,
            }
            raise IdGeneratorError(error_context)

        self.id_attribute_name = config["id_attribute_name"]
        self.identifiers_spec = [
            {
                **item,
                "serialize": item.get("serialize") or config.get("serialize"),
                "hash": {**config.get("hash", {}), **item.get("hash", {})},
                "scope": (
                    item.get("scope") if "scope" in item.keys() else config.get("scope")
                ),
            }
            for item in config["identifiers_spec"]
        ]

    @logging_wrapper(logger)
    def process(self, context, internal_data):
        mdstore = internal_data.get("metadata", {})
        issuer = internal_data.auth_info.issuer
        saml_attributes = {
            attr_name: values
            for int_name, values in internal_data.attributes.items()
            for attr_name in self.internal_to_saml.get(int_name, [])
        }

        searchers_adapted = {
            **searchers,
            "attribute": lambda n: search_attribute(saml_attributes, n),
            "element": lambda n: search_element(internal_data, n),
            "metadata": lambda n: search_metadata(mdstore, issuer, n),
        }
        evaluator = SpecEvaluator(searchers_adapted, operators, serializers, issuer)

        identifiers_spec = evaluator.evaluate_identifiers_specs(self.identifiers_spec)
        identifiers_spec_satisfied = [
            e for e in identifiers_spec if e["satisfied"] and e["values"]
        ]
        identifiers_values = [v for e in identifiers_spec_satisfied for v in e["values"]]
        identifiers_values_uniq = list(OrderedDict.fromkeys(identifiers_values))

        log_data = {
            "message": "Id spec satisfied",
            "issuer": issuer,
            "internal_to_saml": self.internal_to_saml,
            "attributes": saml_attributes.keys(),
            "id_spec_satisfied": identifiers_spec_satisfied,
        }
        logger.info(log_data)

        internal_data.attributes[self.id_attribute_name] = identifiers_values_uniq
        return super().process(context, internal_data)


class SpecEvaluator(object):
    def __init__(self, searchers, operators, serializers, issuer):
        self.searchers = searchers
        self.operators = operators
        self.serializers = serializers
        self.issuer = issuer

    def evaluate_identifiers_specs(self, identifiers_spec):
        evaluated = [self.evaluate_identifiers(spec) for spec in identifiers_spec]
        return evaluated

    def evaluate_identifiers(self, identifier_spec):
        requirements = self.evaluate_requirements(identifier_spec["requirements"])
        satisfied = all(operation["value"] for operation in requirements)
        selections = self.evaluate_entities(identifier_spec["selections"])

        serializer_type = identifier_spec["serialize"]
        hash_conf = identifier_spec["hash"]
        scope = identifier_spec.get("scope")
        identifiers = generate_id(
            serializer=self.serializers.get(serializer_type),
            hasher=lambda value: generate_hash(
                hash_conf["salt"], value, hash_alg=hash_conf.get("algo", "sha512")
            ),
            scoper=lambda value: append_scope(scope, value) if scope else value,
            issuer=self.issuer,
            properties=selections,
        )

        node = {
            **identifier_spec,
            "requirements": requirements,
            "satisfied": satisfied,
            "selections": selections,
            "values": identifiers,
        }
        return node

    def evaluate_entities(self, entities_spec):
        return [self.evaluate_entity(spec) for spec in entities_spec]

    def evaluate_requirements(self, requirements_spec):
        return [self.evaluate_operation(spec) for spec in requirements_spec]

    def evaluate_operation(self, operation_spec):
        operator = self.operators[operation_spec["type"]]
        operands = [self.evaluate_entity(e) for e in operation_spec["operands"]]
        operands_values = [o["value"] for o in operands]
        result = operator(*operands_values)
        node = {**operation_spec, "operands": operands, "value": result}
        return node

    def evaluate_entity(self, entity_spec):
        node = {**entity_spec, "value": self.valuate(entity_spec)}
        return node

    def valuate(self, entity_spec):
        searcher = self.searchers[entity_spec["type"]]
        value = searcher(entity_spec)
        return value


def append_scope(scope, value):
    scoped_value = "{value}@{scope}".format(value=value, scope=scope)
    return scoped_value


def generate_hash(salt, value, hash_alg="sha512"):
    if hash_alg == "plain-text":
        return value

    if not isinstance(value, bytes):
        value = value.encode("utf-8")
    if not isinstance(salt, bytes):
        salt = salt.encode("utf-8")
    hasher = hashlib.new(hash_alg)
    hasher.update(value)
    hasher.update(salt)
    hashed_value = hasher.hexdigest()
    return hashed_value


def generate_id(serializer, hasher, scoper, issuer, properties):
    seeds = serializer(properties)
    hashed_ids = (
        hasher(seed)
        for seed in seeds
    )
    scoped_ids = (
        scoper(hashed_id)
        for hashed_id in hashed_ids
    )
    final_ids = list(scoped_ids)
    return final_ids


def concatenate_all_values(properties):
    """
    example return value:

        ['IDP_WITH_RNS_SUPPORTsome-eppnsome-eptidsome-eptid-2']
    """

    values = [
        v
        for p in properties
        if p["value"]
        for v in ([p["value"]] if type(p["value"]) is str else p["value"])
    ]
    result = "".join(values)
    results = [result]
    return results


def serialize_all_values_as_json_array(properties):
    """
    example return value:

        ['["IDP_WITH_RNS_SUPPORT", ["some-eppn"], ["some-eptid-2", "some-eptid"]]']
    """

    values = [p["value"] for p in properties]
    result = json.dumps(values)
    results = [result]
    return results


def serialize_properties_with_all_values_as_json_obj(properties):
    """
    example return value:

        ['{"eduPersonPrincipalName":["some-eppn"],"eduPersonTargetedID":["some-eptid-2","some-eptid"],"issuer":"IDP_WITH_RNS_SUPPORT"}']
    """

    obj = {p["name"]: p["value"] for p in properties}
    result = json.dumps(
        obj, sort_keys=True, indent=None, default=None, separators=(',', ':')
    )
    results = [result]
    return results


def serialize_combinations_of_properties_with_separate_values_as_json_obj(properties):
    """
    example return value:

        >>> pairs_of_properties_and_list_values
        [
            ('issuer', ['IDP_WITH_RNS_SUPPORT']),
            ('eduPersonPrincipalName', ['some-eppn']),
            ('eduPersonTargetedID', ['some-eptid', 'some-eptid-2'])
        ]

        >>> entries_of_pairs_of_properties_and_separate_values
        [
            [
                ('issuer', 'IDP_WITH_RNS_SUPPORT')
            ],
            [
                ('eduPersonPrincipalName', 'some-eppn')
            ],
            [
                ('eduPersonTargetedID', 'some-eptid'),
                ('eduPersonTargetedID', 'some-eptid-2')
            ]
        ]

        >>> combos_of_single_value_properties
        [
            (
                ('issuer', 'IDP_WITH_RNS_SUPPORT'),
                ('eduPersonPrincipalName', 'some-eppn'),
                ('eduPersonTargetedID', 'some-eptid')
            ),
            (
                ('issuer', 'IDP_WITH_RNS_SUPPORT'),
                ('eduPersonPrincipalName', 'some-eppn'),
                ('eduPersonTargetedID', 'some-eptid-2')
            )
        ]

        >>> objs_of_single_value_properties
        [
            {
                'issuer': 'IDP_WITH_RNS_SUPPORT',
                'eduPersonPrincipalName': 'some-eppn',
                'eduPersonTargetedID': 'some-eptid'
            },
            {
                'issuer': 'IDP_WITH_RNS_SUPPORT',
                'eduPersonPrincipalName': 'some-eppn',
                'eduPersonTargetedID': 'some-eptid-2'
            }
        ]

        >>> serialized_objects
        [
            '{"eduPersonPrincipalName":"some-eppn","eduPersonTargetedID":"some-eptid","issuer":"IDP_WITH_RNS_SUPPORT"}',
            '{"eduPersonPrincipalName":"some-eppn","eduPersonTargetedID":"some-eptid-2","issuer":"IDP_WITH_RNS_SUPPORT"}'
        ]
    """

    pairs_of_properties_and_list_values = list(
        (
            p["name"],
            ([p["value"]] if type(p["value"]) is str else p["value"]),
        )
        for p in properties
        if p["value"]
    )
    entries_of_pairs_of_properties_and_separate_values = list(
        list(product([prop], values))
        for prop, values in pairs_of_properties_and_list_values
    )
    combos_of_single_value_properties = list(
        product(*entries_of_pairs_of_properties_and_separate_values)
    )
    objs_of_single_value_properties = list(
        dict(item) for item in combos_of_single_value_properties
    )
    serialized_objects = list(
        json.dumps(
            obj, sort_keys=False, indent=None, default=None, separators=(',', ':')
        )
        for obj in objs_of_single_value_properties
    )
    results = list(serialized_objects)
    return results


serializers = {
    "concat": concatenate_all_values,
    "struct": serialize_all_values_as_json_array,
    "struct_obj": serialize_properties_with_all_values_as_json_obj,
    "struct_obj_combo": serialize_combinations_of_properties_with_separate_values_as_json_obj,
}


def search_metadata_supported_entity_categories(mdstore, issuer):
    value = mdstore.get(issuer, {}).get("supported_entity_categories", [])
    return value


def search_metadata_entity_categories(mdstore, issuer):
    value = mdstore.get(issuer, {}).get("entity_categories", [])
    return value


def search_metadata_registration_authority_name(mdstore, issuer):
    value = mdstore.get(issuer, {}).get("registration_info", {}).get("registration_authority")
    return value


def search_metadata(mdstore, issuer, spec):
    data_name = spec["name"]
    searcher = searchers_metadata[data_name]
    value = searcher(mdstore, issuer)
    return value


searchers_metadata = {
    "entity-category-support": search_metadata_supported_entity_categories,
    "entity-category": search_metadata_entity_categories,
    "registration-authority-name": search_metadata_registration_authority_name,
}


def search_element_name_id(internal_data):
    value = internal_data.subject_id
    return value


def search_element_name_id_format(internal_data):
    value = internal_data.subject_type
    return value


def search_element_issuer(internal_data):
    value = internal_data.auth_info.issuer
    return value


def search_element_requester(internal_data):
    value = internal_data.requester
    return value


def search_element_authority(internal_data):
    value = getattr(internal_data.auth_info, 'authority', None)
    return value


def search_element(internal_data, spec):
    element_name = spec["name"]
    searcher = searchers_element[element_name]
    value = searcher(internal_data)
    return value


searchers_element = {
    "name_id": search_element_name_id,
    "name_id_format": search_element_name_id_format,
    "issuer": search_element_issuer,
    "requester": search_element_requester,
    "authority": search_element_authority,
}


def search_attribute(attributes, spec):
    attribute_name = spec["name"]
    value = attributes.get(attribute_name, [])
    return value


def search_value(spec):
    value = spec["value"]
    return value


searchers = {
    "attribute": search_attribute,
    "element": search_element,
    "metadata": search_metadata,
    "value": search_value,
}


operators = {
    op: imp
    for op in ["contains", "eq", "truth"]
    for op, imp in {
        op: getattr(operator, op),
        "not-" + op: lambda *args, op=op: not getattr(operator, op)(*args),
    }.items()
}
