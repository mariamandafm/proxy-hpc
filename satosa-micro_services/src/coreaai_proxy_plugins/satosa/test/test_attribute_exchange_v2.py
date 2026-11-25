from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.attribute_exchange import AttributeExchangeV2 as Plugin
from coreaai_proxy_plugins.satosa.micro_services.attribute_exchange.v2 import CopyStrategy

import pytest


@pytest.fixture
def default_context():
    context = Context()
    context.state = State()
    return context


@pytest.fixture
def target_attr_name():
    return "target"


@pytest.fixture
def target_attr_values():
    values = [
        "tv1",
        "tv2",
    ]
    return values


@pytest.fixture
def source1_attr_name():
    return "source1"


@pytest.fixture
def source1_attr_values():
    values = [
        "s1v1",
        "s1v2",
    ]
    return values


@pytest.fixture
def source2_attr_name():
    return "source2"


@pytest.fixture
def source2_attr_values():
    values = [
        "s2v1",
        "s2v2",
        "s2v3",
    ]
    return values


@pytest.fixture
def copy_one_overwrite_missing_source(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name],
                        "strategy": CopyStrategy.OVERWRITE.value,
                        "clear_source": False,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source2_attr_name: source2_attr_values,
            target_attr_name: [*target_attr_values],
        },
    }


@pytest.fixture
def copy_one_overwrite_missing_target(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name],
                        "strategy": CopyStrategy.OVERWRITE.value,
                        "clear_source": False,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: [*source1_attr_values],
        },
    }


@pytest.fixture
def copy_one_merge_missing_target(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name],
                        "strategy": CopyStrategy.MERGE.value,
                        "clear_source": False,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: [*source1_attr_values],
        },
    }


@pytest.fixture
def copy_one_overwrite_missing_source_target(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name],
                        "strategy": CopyStrategy.OVERWRITE.value,
                        "clear_source": False,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source2_attr_name: source2_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source2_attr_name: source2_attr_values,
        },
    }


@pytest.fixture
def copy_one_overwrite(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name],
                        "strategy": CopyStrategy.OVERWRITE.value,
                        "clear_source": False,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: [*source1_attr_values],
        },
    }


@pytest.fixture
def copy_one_merge(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name],
                        "strategy": CopyStrategy.MERGE.value,
                        "clear_source": False,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: [*target_attr_values, *source1_attr_values],
        },
    }


@pytest.fixture
def copy_many_overwrite(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name, source2_attr_name],
                        "strategy": CopyStrategy.OVERWRITE.value,
                        "clear_source": False,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: [*source1_attr_values, *source2_attr_values],
        },
    }


@pytest.fixture
def copy_many_merge(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name, source2_attr_name],
                        "strategy": CopyStrategy.MERGE.value,
                        "clear_source": False,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: [
                *target_attr_values, *source1_attr_values, *source2_attr_values
            ],
        },
    }


@pytest.fixture
def copy_one_overwrite_clear(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name],
                        "strategy": CopyStrategy.OVERWRITE.value,
                        "clear_source": True,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source2_attr_name: source2_attr_values,
            target_attr_name: [*source1_attr_values],
        },
    }


@pytest.fixture
def copy_one_merge_clear(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name],
                        "strategy": CopyStrategy.MERGE.value,
                        "clear_source": True,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            source2_attr_name: source2_attr_values,
            target_attr_name: [*target_attr_values, *source1_attr_values],
        },
    }


@pytest.fixture
def copy_many_overwrite_clear(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name, source2_attr_name],
                        "strategy": CopyStrategy.OVERWRITE.value,
                        "clear_source": True,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            target_attr_name: [*source1_attr_values, *source2_attr_values],
        },
    }


@pytest.fixture
def copy_many_merge_clear(
    target_attr_name,
    target_attr_values,
    source1_attr_name,
    source1_attr_values,
    source2_attr_name,
    source2_attr_values,
):
    return {
        "provided_config": [
            {
                "copy_rules": [
                    {
                        "target_attribute": target_attr_name,
                        "source_attributes": [source1_attr_name, source2_attr_name],
                        "strategy": CopyStrategy.MERGE.value,
                        "clear_source": True,
                    }
                ]
            }
        ],
        "provided_attributes": {
            "foo": ["bar"],
            source1_attr_name: source1_attr_values,
            source2_attr_name: source2_attr_values,
            target_attr_name: target_attr_values,
        },
        "expected_attributes": {
            "foo": ["bar"],
            target_attr_name: [
                *target_attr_values, *source1_attr_values, *source2_attr_values
            ],
        },
    }


@pytest.mark.parametrize(
    "setup_fixture",
    [
        "copy_one_overwrite_missing_source",
        "copy_one_overwrite_missing_target",
        "copy_one_merge_missing_target",
        "copy_one_overwrite_missing_source_target",
        "copy_one_overwrite",
        "copy_one_merge",
        "copy_many_overwrite",
        "copy_many_merge",
        "copy_one_overwrite_clear",
        "copy_one_merge_clear",
        "copy_many_overwrite_clear",
        "copy_many_merge_clear",
    ],
)
def test_entitlements(
    default_context,
    setup_fixture,
    request,
):
    setup = request.getfixturevalue(setup_fixture)
    config = setup["provided_config"]
    attrs_provided = setup["provided_attributes"]
    attrs_expected = setup["expected_attributes"]

    data = InternalData(attributes=attrs_provided)
    plugin = Plugin(config, "name", "base_url")
    plugin.next = lambda context, data: (context, data)
    _, data = plugin.process(default_context, data)

    assert data.attributes == attrs_expected
