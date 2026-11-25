import logging

from satosa.micro_services.base import RequestMicroService
from satosa.exception import SATOSAError

from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class CustomRoutingError(SATOSAError):
    """Generic error for this module"""


class DecideBackendByRequester(RequestMicroService):
    """
    Select which backend should be used based on who the requester is.

    example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.custom_routing.DecideBackendByRequester
    name: choose-backend-by-requester
    config:
      backend_by_requester:
        requester_id_x: backend_name_1
        requester_id_y: backend_name_1
        requester_id_z: backend_name_2
        default: backend_name_fallback
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        backend_by_requester = config.get("backend_by_requester") or {}
        fallback_backends_service_ids = ["default", ""]

        validators = {
            "backend_by_requester config option must be defined": (
                bool(backend_by_requester)
            ),
            "backend_by_requester must be a dict of str to str": (
                type(backend_by_requester) is dict
                and all(
                    type(requester) is str and type(backend) is str
                    for requester, backend in backend_by_requester.items()
                )
            ),
            "a fallback backend must be defined": (
                type(backend_by_requester) is dict
                and any(
                    fallback_key in backend_by_requester
                    for fallback_key in fallback_backends_service_ids
                )
            ),
        }
        if not all(validators.values()):
            error_context = {
                "message": " ".join(
                    [
                        "The configuration for this plugin is not valid.",
                        "Make sure that the following rules are met:",
                        ", ".join(validators.keys()),
                    ]
                ),
                "validators": validators,
                "config": config,
            }
            raise CustomRoutingError(error_context)

        fallback_backends = [
            backend_by_requester.pop(f, None)
            for f in fallback_backends_service_ids
        ]
        fallback_backend = next((f for f in fallback_backends if f), None)

        self.backend_by_requester = backend_by_requester
        self.fallback_backend = fallback_backend

    @logging_wrapper(logger)
    def process(self, context, data):
        requester = data.requester
        selected_backend = self.backend_by_requester.get(
            requester, self.fallback_backend
        )

        report = {
            "requester": requester,
            "selected_backend": selected_backend,
        }
        logger.info(report)

        context.target_backend = selected_backend
        return super().process(context, data)
