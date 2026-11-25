from logging import getLogger as get_logger

from satosa.internal import InternalData
from satosa.context import Context
from satosa.micro_services.base import RequestMicroService

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(get_logger(__name__))


class PreserveAuthorizations(RequestMicroService):
    """Preserve the requested OIDC scopes in the SATOSA state.

    Reads the requested scopes from the frontend's stored OIDC request
    (``state[target_frontend]["oidc_request"]["scope"]``) and stores them as a
    list under the configured ``authorizations_state_key``, for later use in the
    pipeline. The stored list is empty when no OIDC request/scope is present.

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.authorizations.PreserveAuthorizations
    name: PreserveAuthorizations
    config:
      authorizations_state_key: authorizations
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authorizations_state_key = config["authorizations_state_key"]

    @logging_wrapper(logger)
    def process(self, context: Context, data: InternalData):
        authorizations = (
            context.state.get(context.target_frontend, {})
            .get("oidc_request", {})
            .get("scope", "")
            .split()
        )

        log_context = {
            "message": "Authorizations",
            "authorizations": authorizations,
        }
        logger.info(log_context)

        context.state[self.authorizations_state_key] = authorizations
        return super().process(context, data)
