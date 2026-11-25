import pytest
from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.authn_id_deriver import (
    AuthnIdDeriver,
    AuthnIdDeriverError,
)


@pytest.fixture
def authority():
    return "https://aai.mock-authority.org"


@pytest.fixture
def authn_id_attr():
    return "authn_id"


@pytest.fixture
def default_config(authn_id_attr):
    return [
        {
            "authn_id_attr": authn_id_attr,
        }
    ]


@pytest.fixture
def skip_config(default_config):
    default_config[0]["skip"] = True
    return default_config


@pytest.fixture
def default_context():
    context = Context()
    context.state = State()
    return context


@pytest.mark.parametrize(
    "config",
    [
        pytest.param([], id="empty_config"),
        pytest.param(
            [
                {
                    "authn_id_attr": None,
                }
            ],
            id="empty_authn_id_attr",
        ),
    ],
)
def test_invalid_config(config):
    with pytest.raises(AuthnIdDeriverError):
        AuthnIdDeriver(config, "name", "baseUrl")


def test_valid_authority(
    default_config,
    default_context,
    authority,
    authn_id_attr,
):
    internal_data = InternalData(
        auth_info={"authority": authority},
        attributes={},
    )

    authn_id_deriver = AuthnIdDeriver(
        default_config,
        "name",
        "baseUrl",
    )
    authn_id_deriver.next = lambda context, data: True

    authn_id_deriver.process(default_context, internal_data)
    assert internal_data.attributes[authn_id_attr] == [authority]


def test_empty_authority(
    default_config,
    default_context,
    authn_id_attr,
):
    internal_data = InternalData(
        auth_info={"authority": None},
        attributes={},
    )

    authn_id_deriver = AuthnIdDeriver(
        default_config,
        "name",
        "baseUrl",
    )
    authn_id_deriver.next = lambda context, data: True

    authn_id_deriver.process(default_context, internal_data)
    assert authn_id_attr not in internal_data.attributes


def test_skip_config(
    skip_config,
    default_context,
    authn_id_attr,
):
    internal_data = InternalData(
        auth_info={"authority": None},
        attributes={},
    )

    authn_id_deriver = AuthnIdDeriver(
        skip_config,
        "name",
        "baseUrl",
    )
    authn_id_deriver.next = lambda context, data: True

    authn_id_deriver.process(default_context, internal_data)
    assert authn_id_attr not in internal_data.attributes
