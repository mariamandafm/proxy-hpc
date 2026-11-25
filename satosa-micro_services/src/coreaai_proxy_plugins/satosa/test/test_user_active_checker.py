import pytest
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.user_active_checker import (
    UserActiveChecker,
    UserActiveCheckerError,
)


@pytest.fixture
def user_status_attr():
    return "user_status"


@pytest.fixture
def redirect_url():
    return "https://some-redirect-url.com/random-path"


@pytest.fixture
def active_value():
    return "ActivatedUser"


@pytest.fixture
def default_config(
    user_status_attr,
    redirect_url,
    active_value,
):
    return [
        {
            "user_status_attr": user_status_attr,
            "redirect_url": redirect_url,
            "active_value": active_value,
        }
    ]


@pytest.fixture
def skip_config(
    default_config,
):
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
                    "user_status_attr": "some-field",
                    "redirect_url": "not-a-url",
                    "active_value": "val",
                }
            ],
            id="redirect_url_not_a_url",
        ),
        pytest.param(
            [
                {
                    "user_status_attr": None,
                    "redirect_url": "https://redirect.com",
                    "active_value": "val",
                }
            ],
            id="user_status_attr_none",
        ),
        pytest.param(
            [
                {
                    "user_status_attr": "attr",
                    "redirect_url": "https://redirect.com",
                    "active_value": None,
                }
            ],
            id="active_value_none",
        ),
    ],
)
def test_invalid_config(config):
    with pytest.raises(UserActiveCheckerError):
        UserActiveChecker(config, "name", "baseUrl")


def test_user_active(
    default_config,
    default_context,
    user_status_attr,
    active_value,
):
    internal_data = InternalData(
        attributes={user_status_attr: [active_value]},
    )

    user_active_checker = UserActiveChecker(
        default_config,
        "name",
        "baseUrl",
    )
    user_active_checker.next = lambda context, data: True

    result = user_active_checker.process(default_context, internal_data)

    assert result is True


def test_skip_config(
    skip_config,
    default_context,
    user_status_attr,
    active_value,
):
    internal_data = InternalData(
        attributes={user_status_attr: [active_value]},
    )

    user_active_checker = UserActiveChecker(
        skip_config,
        "name",
        "baseUrl",
    )
    user_active_checker.next = lambda context, data: True

    result = user_active_checker.process(default_context, internal_data)

    assert result is True


def test_user_inactive(
    default_config,
    default_context,
    user_status_attr,
    redirect_url,
):
    internal_data = InternalData(
        attributes={user_status_attr: ["NOT_ACTIVE"]},
    )

    user_active_checker = UserActiveChecker(
        default_config,
        "name",
        "baseUrl",
    )
    user_active_checker.next = lambda context, data: True

    result = user_active_checker.process(default_context, internal_data)

    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))

    assert isinstance(result, Redirect)
    assert str(location_header[1]) == redirect_url


def test_missing_attribute(
    default_config,
    default_context,
    redirect_url,
):
    internal_data = InternalData(
        attributes={},
    )

    user_active_checker = UserActiveChecker(
        default_config,
        "name",
        "baseUrl",
    )
    user_active_checker.next = lambda context, data: True

    result = user_active_checker.process(default_context, internal_data)

    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))

    assert isinstance(result, Redirect)
    assert str(location_header[1]) == redirect_url
