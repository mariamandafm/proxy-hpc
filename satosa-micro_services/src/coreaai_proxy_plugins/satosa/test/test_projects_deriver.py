from satosa.context import Context
from satosa.internal import AuthenticationInformation
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.projects_deriver import ProjectsDeriver

import pytest


@pytest.fixture
def entitlements_attribute_name():
    return "entitlements"


@pytest.fixture
def entitlements_ns():
    return "urn:example:domain.tld"


@pytest.fixture
def entitlements_vo_name():
    return "foo"


@pytest.fixture
def add_entitlements_gp_role_member():
    return True


@pytest.fixture
def replace_entitlements_values():
    return True


@pytest.fixture
def derive_role_from_entitlement_groups():
    return True


@pytest.fixture
def project_attributes_names():
    return ["groups", "eunode_projects"]


@pytest.fixture
def project_regexes(entitlements_ns):
    return [
        f"^{entitlements_ns}:group:(pp-.+).*$",
        f"^{entitlements_ns}:group:(gp-.+(?=:role=))",
        #f"^{entitlements_ns}:group:(?P<groups>gp-.+(?=:role=)):role=(?P<role>[^:]+)$",
    ]


@pytest.fixture
def replace_project_values():
    return True


@pytest.fixture
def default_config(
    entitlements_attribute_name,
    entitlements_ns,
    entitlements_vo_name,
    add_entitlements_gp_role_member,
    replace_entitlements_values,
    derive_role_from_entitlement_groups,
    project_attributes_names,
    project_regexes,
    replace_project_values,
):
    return [
        {
            "entitlements_attribute_name": entitlements_attribute_name,
            "entitlements_ns": entitlements_ns,
            "entitlements_vo_name": entitlements_vo_name,
            "add_entitlements_gp_role_member": add_entitlements_gp_role_member,
            "replace_entitlements_values": replace_entitlements_values,
            "derive_role_from_entitlement_groups": derive_role_from_entitlement_groups,
            "project_attributes_names": project_attributes_names,
            "project_regexes": project_regexes,
            "replace_project_values": replace_project_values,
        }
    ]


@pytest.fixture
def default_context():
    context = Context()
    context.state = State()
    return context


@pytest.fixture
def entitlements_values_aarc_wo_vo(entitlements_ns):
    return {
        "provided": [
            f"{entitlements_ns}:group:pp-123",
            f"{entitlements_ns}:group:gp-456",
            f"{entitlements_ns}:group:gp-789:role=owner",
        ],
        "expected": [
            f"{entitlements_ns}:group:pp-123",
            f"{entitlements_ns}:group:gp-456:role=member",
            f"{entitlements_ns}:group:gp-789:role=owner",
        ],
        "projects": [
            "pp-123",
            "gp-456",
            "gp-789",
        ],
    }


@pytest.fixture
def entitlements_values_aarc_w_vo(entitlements_ns, entitlements_vo_name):
    return {
        "provided": [
            f"{entitlements_ns}:group:{entitlements_vo_name}:pp-a123",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a456",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a789:role=member",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a012:role=admin",
        ],
        "expected": [
            f"{entitlements_ns}:group:pp-a123",
            f"{entitlements_ns}:group:gp-a456:role=member",
            f"{entitlements_ns}:group:gp-a789:role=member",
            f"{entitlements_ns}:group:gp-a012:role=admin",
        ],
        "projects": [
            "pp-a123",
            "gp-a456",
            "gp-a789",
            "gp-a012",
        ],
    }


@pytest.fixture
def entitlements_values_aarc_mix_vo(entitlements_ns, entitlements_vo_name):
    return {
        "provided": [
            f"{entitlements_ns}:group:{entitlements_vo_name}:pp-a123",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a456",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a789:role=member",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a012:role=admin",
            f"{entitlements_ns}:group:gp-b123",
            f"{entitlements_ns}:group:gp-b456:role=member",
        ],
        "expected": [
            f"{entitlements_ns}:group:pp-a123",
            f"{entitlements_ns}:group:gp-a456:role=member",
            f"{entitlements_ns}:group:gp-a789:role=member",
            f"{entitlements_ns}:group:gp-a012:role=admin",
            f"{entitlements_ns}:group:gp-b123:role=member",
            f"{entitlements_ns}:group:gp-b456:role=member",
        ],
        "projects": [
            "pp-a123",
            "gp-a456",
            "gp-a789",
            "gp-a012",
            "gp-b123",
            "gp-b456",
        ],
    }


@pytest.fixture
def entitlements_values_mix(entitlements_ns, entitlements_vo_name):
    return {
        "provided": [
            f"{entitlements_ns}:group:{entitlements_vo_name}:pp-a123",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a456",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a789:role=member",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-a012:role=admin",
            f"{entitlements_ns}:group:gp-b123",
            f"{entitlements_ns}:group:gp-b456:role=member",
            # non Personal or Group Project entitlements
            f"{entitlements_ns}:group:asg:service1:role=viewer",
            f"{entitlements_ns}:group:asg:service2:role=su",
            # non AARC formatted values
            "some-non-aarc-value1",
            "some-non-aarc-value2",
            # Group Project entitlements with alternative role information format
            f"{entitlements_ns}:group:{entitlements_vo_name}:pp-alt123",
            f"{entitlements_ns}:group:{entitlements_vo_name}:pp-alt123:__role__",
            f"{entitlements_ns}:group:{entitlements_vo_name}:pp-alt123:__role__:member",
            f"{entitlements_ns}:group:{entitlements_vo_name}:pp-alt123:__role__:owner",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-alt456",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-alt456:__role__",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-alt456:__role__:member",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-alt456:__role__:owner",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-alt789",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-alt789:__role__",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-alt789:__role__:member",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-alt789:__role__:admin",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-foo",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-foo:bar",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-foo:bar:__role__:member",
            f"{entitlements_ns}:group:{entitlements_vo_name}:gp-foo:bar:__role__:admin",
            # Other Project entitlements as groups with no prefix
            f"{entitlements_ns}:group:{entitlements_vo_name}:11945e44-c52a-46d9-9f65-fc5fe6dfbec4",
            f"{entitlements_ns}:group:{entitlements_vo_name}:11945e44-c52a-46d9-9f65-fc5fe6dfbec4:__role__",
            f"{entitlements_ns}:group:{entitlements_vo_name}:11945e44-c52a-46d9-9f65-fc5fe6dfbec4:__role__:admin",
        ],
        "expected": [
            f"{entitlements_ns}:group:pp-a123",
            f"{entitlements_ns}:group:gp-a456:role=member",
            f"{entitlements_ns}:group:gp-a789:role=member",
            f"{entitlements_ns}:group:gp-a012:role=admin",
            f"{entitlements_ns}:group:gp-b123:role=member",
            f"{entitlements_ns}:group:gp-b456:role=member",
            # keep non Personal or Group Project entitlements
            f"{entitlements_ns}:group:asg:service1:role=viewer",
            f"{entitlements_ns}:group:asg:service2:role=su",
            # keep non AARC formatted values
            "some-non-aarc-value1",
            "some-non-aarc-value2",
            # Group Project entitlements with alternative role information format
            f"{entitlements_ns}:group:gp-foo:role=member",
            f"{entitlements_ns}:group:pp-alt123",
            f"{entitlements_ns}:group:gp-alt456:role=member",
            f"{entitlements_ns}:group:gp-alt456:role=owner",
            f"{entitlements_ns}:group:gp-alt789:role=member",
            f"{entitlements_ns}:group:gp-alt789:role=admin",
            f"{entitlements_ns}:group:gp-foo:bar:role=member",
            f"{entitlements_ns}:group:gp-foo:bar:role=admin",
            # Other Project entitlements as groups with no prefix
            f"{entitlements_ns}:group:11945e44-c52a-46d9-9f65-fc5fe6dfbec4:role=admin",
        ],
        "projects": [
            "pp-a123",
            "gp-a456",
            "gp-a789",
            "gp-a012",
            "gp-b123",
            "gp-b456",
            # Group Project entitlements with alternative role information format
            "gp-foo",
            "pp-alt123",
            "gp-alt456",
            "gp-alt789",
            "gp-foo:bar",
        ],
    }


@pytest.mark.parametrize(
    "entitlements_values_fixture",
    [
        "entitlements_values_aarc_wo_vo",
        "entitlements_values_aarc_w_vo",
        "entitlements_values_aarc_mix_vo",
        "entitlements_values_mix",
    ],
)
def test_entitlements(
    default_config,
    default_context,
    entitlements_attribute_name,
    project_attributes_names,
    entitlements_values_fixture,
    request,
):
    entitlements_values = request.getfixturevalue(entitlements_values_fixture)
    provided = entitlements_values["provided"]
    expected = entitlements_values["expected"]
    expected_projects = entitlements_values["projects"]

    data = InternalData(attributes={entitlements_attribute_name: provided})
    plugin = ProjectsDeriver(default_config, "name", "base_url")
    plugin.next = lambda context, data: (context, data)
    _, data = plugin.process(default_context, data)

    assert data.attributes.get(entitlements_attribute_name) == expected
    for claim in project_attributes_names:
        assert data.attributes[claim] == expected_projects
