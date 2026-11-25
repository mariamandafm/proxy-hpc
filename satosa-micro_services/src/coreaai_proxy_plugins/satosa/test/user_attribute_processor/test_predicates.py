import pytest
from satosa.internal import InternalData

from coreaai_proxy_plugins.satosa.micro_services.user_attribute_processor.attributes import Attribute
from coreaai_proxy_plugins.satosa.micro_services.user_attribute_processor.predicates import (
    Predicate,
    IsContainedInStaticList,
    RegexMatch,
    AlwaysTrue,
    AlwaysFalse,
    OrComposition,
    AndComposition,
    NotOperator,
    PredicateException,
)


def gen_always_true():
    return {
        "name": "always_true",
    }


def gen_always_false():
    return {
        "name": "always_false",
    }


def test_is_contained_in_static_list():
    predicate = Predicate(
        condition={
            "name": "is_contained_in_static_list",
            "source_attribute": {
                "attribute_path": {"name": "user_email_address"},
            },
            "static_list": [
                "test1@email.com",
                "test2@email.com",
            ],
        }
    )

    assert isinstance(predicate.condition, IsContainedInStaticList)

    source = InternalData(
        attributes={"mail": "test2@email.com"},
    )

    assert predicate.check(source)

    source = InternalData(
        attributes={"mail": "test3@email.com"},
    )

    assert not predicate.check(source)

    source = InternalData(
        attributes={"mail": ["test2@email.com"]},
    )

    assert predicate.check(source)

    source = InternalData(
        attributes={"mail": ["test3@email.com"]},
    )

    assert not predicate.check(source)

    predicate = Predicate(
        condition={
            "name": "is_contained_in_static_list",
            "source_attribute": {
                "attribute_path": {"name": "user_email_address"},
            },
            "ignore_case": True,
            "static_list": [
                "TEST1@EMAIL.COM",
            ],
        }
    )

    source = InternalData(
        attributes={"mail": ["test1@email.com"]},
    )

    assert predicate.check(source)

    source = InternalData(
        attributes={"mail": "test1@email.com"},
    )

    assert predicate.check(source)


def test_regex_match():
    predicate = Predicate(
        condition={
            "name": "regex_match",
            "source_attribute": Attribute(
                attribute_path={"name": "user_email_address"}
            ),
            "regex_pattern": "^.*@email.com",
        }
    )

    predicate_ignore_case = Predicate(
        condition={
            "name": "regex_match",
            "source_attribute": Attribute(
                attribute_path={"name": "user_email_address"}
            ),
            "regex_pattern": "^.*@EMAIL.COM",
            "ignore_case": True,
        }
    )

    assert isinstance(predicate.condition, RegexMatch)

    source = InternalData(
        attributes={"mail": "test1@email.com"},
    )

    assert predicate.check(source)
    assert predicate_ignore_case.check(source)

    source = InternalData(
        attributes={"mail": "test1@notemail.com"},
    )

    assert not predicate.check(source)
    assert not predicate_ignore_case.check(source)


def test_always_true(default_data):
    always_true = Predicate(condition=gen_always_true())
    assert isinstance(always_true.condition, AlwaysTrue)
    assert always_true.check(default_data)


def test_always_false(default_data):
    always_false = Predicate(condition=gen_always_false())
    assert isinstance(always_false.condition, AlwaysFalse)
    assert not always_false.check(default_data)


def test_not(default_data):
    negation = Predicate(
        condition={
            "name": "not",
            "condition": {"name": "always_true"},
        }
    )
    assert isinstance(negation.condition, NotOperator)
    assert not negation.check(default_data)

    negation = Predicate(
        condition={
            "name": "not",
            "condition": {"name": "always_false"},
        }
    )
    assert isinstance(negation.condition, NotOperator)
    assert negation.check(default_data)


def test_or_composition(default_data):
    or_composition = Predicate(
        condition={
            "name": "or",
            "conditions": [gen_always_false(), gen_always_true()],
        }
    )

    assert isinstance(or_composition.condition, OrComposition)
    assert or_composition.check(default_data)

    or_composition = Predicate(
        condition={
            "name": "or",
            "conditions": [gen_always_false(), gen_always_false()],
        }
    )

    assert not or_composition.check(default_data)

    or_composition = Predicate(
        condition={
            "name": "or",
            "conditions": [gen_always_true(), gen_always_true()],
        }
    )

    assert or_composition.check(default_data)

    with pytest.raises(PredicateException):
        Predicate(
            condition={
                "name": "or",
                "conditions": [],
            }
        )


def test_and_composition(default_data):
    and_composition = Predicate(
        condition={
            "name": "and",
            "conditions": [gen_always_false(), gen_always_true()],
        }
    )

    assert isinstance(and_composition.condition, AndComposition)
    assert and_composition.check(default_data) is False

    and_composition = Predicate(
        condition={
            "name": "and",
            "conditions": [gen_always_true(), gen_always_true()],
        }
    )

    assert and_composition.check(default_data) is True

    and_composition = Predicate(
        condition={
            "name": "and",
            "conditions": [gen_always_false(), gen_always_false()],
        }
    )

    assert and_composition.check(default_data) is False

    with pytest.raises(PredicateException):
        Predicate(
            condition={
                "name": "and",
                "conditions": [],
            }
        )
