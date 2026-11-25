import pytest
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

from coreaai_proxy_plugins.satosa.micro_services.policy_agreement_checker import (
    PolicyAgreementChecker,
    PolicyAgreementCheckerError,
)


@pytest.fixture
def user_aup():
    return "v1.0"


@pytest.fixture
def user_tou():
    return "v2.0"


@pytest.fixture
def user_privacy_policy():
    return "v3.0"


@pytest.fixture
def redirect_url():
    return "https://example.com/policy-agreement"


@pytest.fixture
def default_config(redirect_url):
    return [
        {
            "policy_privacy_attr_name": "userPrivacyPolicy",
            "policy_privacy_value": "v3.0",
            "policy_aup_attr_name": "userAup",
            "policy_aup_value": "v1.0",
            "policy_tou_attr_name": "userTou",
            "policy_tou_value": "v2.0",
            "redirect_url": redirect_url
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
                    "policies": {},
                    "redirect_url": "not-a-url",
                }
            ],
            id="redirect_url_not_a_url"
        ),
        pytest.param(
            [
                {
                    "policies": None,
                    "redirect_url": "https://example.com/policy-agreement",
                }
            ],
            id="policies_none"
        ),
        pytest.param(
            [
                {
                    "redirect_url": "https://example.com/policy-agreement",
                }
            ],
            id="policies_not_present"
        ),
    ],
)
def test_invalid_config(config):
    with pytest.raises(PolicyAgreementCheckerError):
        PolicyAgreementChecker(config, "name", "base_url")


def test_policy_not_present(
        default_config,
        default_context,
        user_tou,
        user_privacy_policy,
        redirect_url,
):
    internal_data = InternalData(
        attributes={
            "userAup": [None],
            "userTou": [user_tou],
            "userPrivacyPolicy": [user_privacy_policy],
        }
    )

    policy_agreement_checker = PolicyAgreementChecker(default_config, "name", "base_url")

    policy_agreement_checker.next = lambda context, data: True

    result = policy_agreement_checker.process(default_context, internal_data)

    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))

    assert isinstance(result, Redirect)
    assert str(location_header[1]) == redirect_url


def test_version_match(
    default_config,
    default_context,
    user_aup,
    user_tou,
    user_privacy_policy,
):
    internal_data = InternalData(
        attributes={
            "userAup": [user_aup],
            "userTou": [user_tou],
            "userPrivacyPolicy": [user_privacy_policy],
        }
    )

    policy_agreement_checker = PolicyAgreementChecker(default_config, "name", "base_url")

    policy_agreement_checker.next = lambda context, data: True

    result = policy_agreement_checker.process(default_context, internal_data)

    assert result is True


def test_userAup_version_mismatch(
    default_config,
    default_context,
    user_tou,
    user_privacy_policy,
    redirect_url,
):
    internal_data = InternalData(
        attributes={
            "userAup": ["v2.0"],
            "userTou": [user_tou],
            "userPrivacyPolicy": [user_privacy_policy],
        }
    )

    policy_agreement_checker = PolicyAgreementChecker(default_config, "name", "base_url")

    policy_agreement_checker.next = lambda context, data: True

    result = policy_agreement_checker.process(default_context, internal_data)
    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))

    assert isinstance(result, Redirect)
    assert str(location_header[1]) == redirect_url


def test_user_tou_version_mismatch(
    default_config,
    default_context,
    user_aup,
    user_privacy_policy,
    redirect_url,
):
    internal_data = InternalData(
        attributes={
            "userAup": [user_aup],
            "userTou": ["v3.0"],
            "userPrivacyPolicy": [user_privacy_policy],
        }
    )

    policy_agreement_checker = PolicyAgreementChecker(default_config, "name", "base_url")

    policy_agreement_checker.next = lambda context, data: True

    result = policy_agreement_checker.process(default_context, internal_data)
    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))

    assert isinstance(result, Redirect)
    assert str(location_header[1]) == redirect_url


def test_user_privacy_policy_version_mismatch(
    default_config,
    default_context,
    user_aup,
    user_tou,
    redirect_url,
):
    internal_data = InternalData(
        attributes={
            "userAup": [user_aup],
            "userTou": [user_tou],
            "userPrivacyPolicy": ["v4.0"],
        }
    )

    policy_agreement_checker = PolicyAgreementChecker(default_config, "name", "base_url")

    policy_agreement_checker.next = lambda context, data: True

    result = policy_agreement_checker.process(default_context, internal_data)
    location_header = next(iter(filter(lambda x: x[0] == "Location", result.headers)))

    assert isinstance(result, Redirect)
    assert str(location_header[1]) == redirect_url
