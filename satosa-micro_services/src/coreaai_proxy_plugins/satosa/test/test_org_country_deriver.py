import pytest
from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.org_country_deriver import (
    OrgCountryDeriver,
    OrgCountryDeriverError,
)


@pytest.fixture
def registration_authority(reg_auth_to_country):
    return next(iter(reg_auth_to_country.keys()))


@pytest.fixture
def org_country(reg_auth_to_country, registration_authority):
    return reg_auth_to_country[registration_authority]


@pytest.fixture
def issuer():
    return "https://issuer-url.com/some-path.xml"


@pytest.fixture
def org_country_attr():
    return "org_country"


@pytest.fixture()
def reg_auth_to_country():
    return {
        "http://aai.arnes.si": "SVN",
        "http://aai.grnet.gr/": "GRC",
        "http://arbicon.ru": "RUS",
        "http://cafe.rnp.br": "BRA",
        "http://cofre.reuna.cl": "CHL",
        "http://colfire.co": "COL",
        "http://eduid.at": "AUT",
    }


@pytest.fixture
def default_config(org_country_attr, reg_auth_to_country):
    return [
        {
            "org_country_attr": org_country_attr,
            "reg_auth_to_country": reg_auth_to_country,
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
            [{"org_country_attr": None, "reg_auth_to_country": {}}],
            id="none_org_country_attr",
        ),
        pytest.param(
            [{"org_country_attr": "str", "reg_auth_to_country": None}],
            id="none_mapping",
        ),
    ],
)
def test_invalid_config(config):
    with pytest.raises(OrgCountryDeriverError):
        OrgCountryDeriver(config, "name", "baseUrl")


def test_org_country_found(
    default_config,
    default_context,
    issuer,
    registration_authority,
    org_country_attr,
    org_country,
):
    internal_data = InternalData(
        auth_info={"issuer": issuer},
        metadata={
            issuer: {
                "registration_info": {
                    "registration_authority": registration_authority,
                }
            }
        },
        attributes={},
    )

    plugin = OrgCountryDeriver(
        default_config,
        "name",
        "baseUrl",
    )
    plugin.next = lambda context, data: (context, data)
    v = plugin.process(default_context, internal_data)
    print(v)
    _, newdata = plugin.process(default_context, internal_data)

    print(newdata)
    assert newdata.attributes[org_country_attr] == [org_country]


def test_org_country_not_found(
    default_config,
    default_context,
    issuer,
    registration_authority,
    org_country_attr,
    org_country,
):
    internal_data = InternalData(
        auth_info={"issuer": issuer},
        metadata={
            issuer: {
                "registration_info": {
                    "registration_authority": "https://aai.different-authority.org",
                }
            }
        },
        attributes={},
    )

    plugin = OrgCountryDeriver(
        default_config,
        "name",
        "baseUrl",
    )
    plugin.next = lambda context, data: (context, data)
    newctx, newdata = plugin.process(default_context, internal_data)

    assert org_country_attr not in newdata.attributes


def test_skip_config(
    skip_config,
    default_context,
    issuer,
    registration_authority,
    org_country_attr,
    org_country,
):
    internal_data = InternalData(
        auth_info={"issuer": issuer},
        metadata={
            issuer: {
                "registration_info": {
                    "registration_authority": "https://aai.different-authority.org",
                }
            }
        },
        attributes={},
    )

    plugin = OrgCountryDeriver(
        skip_config,
        "name",
        "baseUrl",
    )
    plugin.next = lambda context, data: (context, data)
    newctx, newdata = plugin.process(default_context, internal_data)

    assert org_country_attr not in newdata.attributes


def test_missing_registration_info(
    default_config,
    default_context,
    issuer,
    org_country_attr,
):
    internal_data = InternalData(
        auth_info={"issuer": issuer},
        metadata={issuer: {}},
        attributes={},
    )

    plugin = OrgCountryDeriver(
        default_config,
        "name",
        "baseUrl",
    )
    plugin.next = lambda context, data: (context, data)
    newctx, newdata = plugin.process(default_context, internal_data)

    assert org_country_attr not in newdata.attributes
