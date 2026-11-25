import pytest
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State


from coreaai_proxy_plugins.satosa.micro_services.user_type_checker import (
    UserTypeChecker,
    UserTypeCheckerError,
)


@pytest.fixture
def registration_status_attr():
    return "registration_status"


@pytest.fixture
def redirect_url():
    return "https://redirect-url.com/register-path"


@pytest.fixture
def registered_value():
    return "userRegistered"


@pytest.fixture
def default_config(registration_status_attr, redirect_url, registered_value):
    return [
        {
            "registration_status_attr": registration_status_attr,
            "redirect_url": redirect_url,
            "registered_value": registered_value,
        }
    ]


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
                    "registration_status_attr": "some-registration-field",
                    "redirect_url": "not-url",
                    "registered_value": "value",
                }
            ],
            id="redirect_url_not_a_url",
        ),
        pytest.param(
            [
                {
                    "registration_status_attr": None,
                    "redirect_url": "https://redirect.com",
                    "registered_value": "value",
                }
            ],
            id="registration_status_attr_none",
        ),
        pytest.param(
            [
                {
                    "user_status_attr": "attr",
                    "redirect_url": "https://redirect.com",
                    "registered_value": None,
                }
            ],
            id="registered_value_none",
        ),
    ],
)
def test_invalid_config(config):
    with pytest.raises(UserTypeCheckerError):
        UserTypeChecker(config, "name", "base_url")


def test_user_registered(
    default_config,
    default_context,
    registration_status_attr,
    registered_value,
):
    internal_data = InternalData(
        attributes={registration_status_attr: [registered_value]}
    )

    user_registered_checker = UserTypeChecker(default_config, "name", "base_url")

    user_registered_checker.next = lambda context, data: True

    result = user_registered_checker.process(default_context, internal_data)

    assert result is True


def test_user_not_registered(
    default_config,
    default_context,
    registration_status_attr,
    redirect_url,
):
    internal_data = InternalData(
        attributes={registration_status_attr: ["NOT_REGISTERED"]}
    )

    user_registered = UserTypeChecker(default_config, "name", "base_url")

    user_registered.next = lambda context, data: True

    result = user_registered.process(default_context, internal_data)

    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))

    assert isinstance(result, Redirect)
    assert str(location_header[1]) == redirect_url


def test_missing_attribute(
    default_config,
    default_context,
    redirect_url
):
    internal_data = InternalData(
        attributes={registration_status_attr: [None]},
    )

    user_registered = UserTypeChecker(default_config, "name", "base_url")

    user_registered.next = lambda context, data: True

    result = user_registered.process(default_context, internal_data)

    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))

    assert isinstance(result, Redirect)
    assert str(location_header[1]) == redirect_url
