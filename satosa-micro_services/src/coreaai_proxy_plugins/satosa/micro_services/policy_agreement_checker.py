import logging
from typing import Sequence

from satosa.context import Context
from satosa.exception import SATOSAError
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect
from satosa.internal import InternalData

from coreaai_proxy_plugins.helpers.config import (
    AnyHttpUrl,
    TableConfig,
    restructure_table_config_to_hierarchical_config,
    resolve_config_wrapper,
)
from coreaai_proxy_plugins.helpers.logging import ExtraLogger, logging_wrapper

logger = ExtraLogger(logging.getLogger(__name__))


class PolicyAgreementCheckerError(SATOSAError):
    pass


class Config(TableConfig):
    policy_privacy_attr_name: str
    policy_privacy_value: str
    policy_aup_attr_name: str
    policy_aup_value: str
    policy_tou_attr_name: str
    policy_tou_value: str
    redirect_url: AnyHttpUrl


class PolicyAgreementChecker(ResponseMicroService):
    """
    Plugin to check if the user has agreed to the latest policies.
    If not, it redirects the user to the policy-agreement page.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.policy_agreement_checker.PolicyAgreementChecker
    name: PolicyAgreementChecker
    config:
        policy_privacy_attr_name: userPrivacyPolicy
        policy_privacy_value: v3.1
        policy_aup_attr_name: userAup
        policy_aup_value: v1.2
        policy_tou_attr_name: userTou
        policy_tou_value: v2.0
        redirect_url: "https://example.com/policy-agreement"
        requester: "{{ entry.requester }}"
        issuer: "{{ entry.issuer }}"
        skip: {{ entry.skip }}
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            table_configs: Sequence[Config] = [
                Config(
                    policy_privacy_attr_name=c["policy_privacy_attr_name"],
                    policy_privacy_value=c["policy_privacy_value"],
                    policy_aup_attr_name=c["policy_aup_attr_name"],
                    policy_aup_value=c["policy_aup_value"],
                    policy_tou_attr_name=c["policy_tou_attr_name"],
                    policy_tou_value=c["policy_tou_value"],
                    redirect_url=c["redirect_url"],
                    requester=c.get("requester"),
                    issuer=c.get("issuer"),
                    skip=c.get("skip"),
                )
                for c in config
            ]
        except Exception as e:
            raise PolicyAgreementCheckerError("Invalid configuration") from e

        if not table_configs:
            raise PolicyAgreementCheckerError("Invalid configuration")

        hierarchical_config = restructure_table_config_to_hierarchical_config(
            table_configs
        )

        self.config = hierarchical_config

    @logging_wrapper(logger)
    @resolve_config_wrapper(logger)
    def process(self, context: Context, data: InternalData, config: Config):
        if not config or config.skip:
            return super().process(context, data)

        policy_aup = next(
            iter(data.attributes.get(config.policy_aup_attr_name) or [None])
        )
        policy_tou = next(
            iter(data.attributes.get(config.policy_tou_attr_name) or [None])
        )
        policy_pri = next(
            iter(data.attributes.get(config.policy_privacy_attr_name) or [None])
        )

        pending_aup = policy_aup != config.policy_aup_value
        pending_tou = policy_tou != config.policy_tou_value
        pending_pri = policy_pri != config.policy_privacy_value
        agreements_pending = any((pending_aup, pending_tou, pending_pri))

        report = {
            "message": "Pending agreements status",
            "agreements_pending": agreements_pending,
            "status": {
                "pending_aup": pending_aup,
                "pending_tou": pending_tou,
                "pending_privacy": pending_pri,
            },
            "required_values": {
                "policy_aup": config.policy_aup_value,
                "policy_tou": config.policy_tou_value,
                "policy_privacy": config.policy_privacy_value,
            },
            "accepted_values": {
                "policy_aup": policy_aup,
                "policy_tou": policy_tou,
                "policy_privacy": policy_pri,
            },
        }
        logger.info(report)

        if agreements_pending:
            return Redirect(config.redirect_url)

        return super().process(context, data)
