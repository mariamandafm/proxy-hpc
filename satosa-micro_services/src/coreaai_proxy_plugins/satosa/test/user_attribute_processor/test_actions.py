from pydantic import BaseModel

from coreaai_proxy_plugins.satosa.micro_services.user_attribute_processor.actions import (
    Action,
    Redirect,
    NextMicroservice,
    AddLiteralAttribute,
)
from satosa.response import Redirect as satosa_redirect


class ActionWrapper(BaseModel):
    action: Action


def test_redirect_action(default_data):
    redirect_url = "https://some-random-url.com/path"
    wrapper = ActionWrapper(action={"name": "redirect", "redirect_url": redirect_url})

    assert isinstance(wrapper.action, Redirect)

    result = wrapper.action.process(default_data)

    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))
    assert isinstance(result, satosa_redirect)
    assert str(location_header[1]) == redirect_url


def test_next_microservice(default_data):
    wrapper = ActionWrapper(
        action={
            "name": "next_microservice",
        }
    )

    assert isinstance(wrapper.action, NextMicroservice)

    result = wrapper.action.process(default_data)

    assert result is None


def test_add_literal_attribute(default_data):
    wrapper = ActionWrapper(
        action={
            "name": "add_literal_attribute",
            "attribute": {
                "attribute_path": {
                    "name": "custom_path",
                    "path": ["attributes", "some", "random", "path"],
                }
            },
            "value": "test_value",
        }
    )

    assert isinstance(wrapper.action, AddLiteralAttribute)

    result = wrapper.action.process(default_data)

    assert result is None
    assert default_data.attributes["some"]["random"]["path"] == "test_value"
