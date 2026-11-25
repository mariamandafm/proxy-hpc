import pytest
from satosa.context import Context
from satosa.internal import InternalData
from satosa.state import State
from satosa.response import Redirect as satosa_redirect

from coreaai_proxy_plugins.satosa.micro_services.user_attribute_processor import (
    UserAttributeProcessor,
    UserAttributeProcessorError,
)


@pytest.fixture
def redirect_url():
    return "https://some-redirect-url.com/random-path"


@pytest.fixture
def default_config(
    redirect_url,
):
    return [
        {
            "rules": [
                {
                    "name": "Redirect if email is not in list",
                    "predicate": {
                        "condition": {
                            "name": "is_contained_in_static_list",
                            "source_attribute": {
                                "attribute_path": {"name": "user_email_address"}
                            },
                            "static_list": [
                                "random.email1@email.com",
                                "random.email2@email.com",
                            ],
                        }
                    },
                    "failure_actions": [
                        {
                            "name": "redirect",
                            "redirect_url": redirect_url,
                        }
                    ],
                }
            ],
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
        pytest.param([{"rules": {}}], id="empty_config_2"),
        pytest.param(
            [
                {
                    "rules": [
                        {
                            "name": "test",
                            "success_actions": [],
                            "failure_actions": [],
                        }
                    ]
                }
            ],
            id="no_predicate",
        ),
    ],
)
def test_invalid_config(config):
    with pytest.raises(UserAttributeProcessorError):
        UserAttributeProcessor(config, "name", "baseUrl")


def test_not_in_list(
    default_config,
    default_context,
    default_data,
    redirect_url,
):
    checker = UserAttributeProcessor(default_config, "name", "baseUrl")

    result = checker.process(default_context, default_data)

    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))
    assert isinstance(result, satosa_redirect)
    assert str(location_header[1]) == redirect_url


def test_in_list(
    default_config,
    default_context,
):
    checker = UserAttributeProcessor(default_config, "name", "baseUrl")

    data = InternalData(
        attributes={"mail": "random.email1@email.com"},
    )

    checker.next = lambda context, data: True

    result = checker.process(default_context, data)

    assert result is True


def test_skip_config(
    skip_config,
    default_context,
    default_data,
):
    user_active_checker = UserAttributeProcessor(
        skip_config,
        "name",
        "baseUrl",
    )
    user_active_checker.next = lambda context, data: True

    result = user_active_checker.process(default_context, default_data)

    assert result is True
