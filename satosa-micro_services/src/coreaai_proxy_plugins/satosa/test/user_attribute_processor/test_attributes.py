import pytest
from satosa.internal import InternalData

from coreaai_proxy_plugins.satosa.micro_services.user_attribute_processor.attributes import (
    UserEmailAddress,
    CustomPath,
    Attribute,
    AttributeNotFoundException,
)


def test_custom_path():
    source = InternalData(
        attributes={"list_attr": [{"value": "THE_VALUE"}]},
    )

    attribute = Attribute(
        attribute_path={
            "name": "custom_path",
            "path": ["attributes", "list_attr", "0", "value"],
        }
    )

    assert isinstance(attribute.attribute_path, CustomPath)

    value = attribute.extract_value(source)

    assert value == "THE_VALUE"

    source = InternalData(
        attributes={"list_attr": ""},
    )

    with pytest.raises(AttributeNotFoundException):
        attribute.extract_value(source)


def test_email_attribute():
    source = InternalData(
        attributes={"mail": "some.email@test.com"},
    )

    attribute = Attribute(attribute_path={"name": "user_email_address"})

    assert isinstance(attribute.attribute_path, UserEmailAddress)

    value = attribute.extract_value(source)

    assert value == "some.email@test.com"

    source = InternalData(
        attributes={"not_email": "some.email@test.com"},
    )

    with pytest.raises(AttributeNotFoundException):
        attribute.extract_value(source)
