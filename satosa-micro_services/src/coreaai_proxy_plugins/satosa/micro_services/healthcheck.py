import json

from satosa.micro_services.base import RequestMicroService
from satosa.response import Response

data = {
    "status": "ok",
}
ok_response = Response(message=json.dumps(data))


class HealthCheck(RequestMicroService):
    """Expose a ``healthcheck`` endpoint returning ``{"status": "ok"}``.

    Request microservice; takes no config. Intended for liveness probes.

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.healthcheck.HealthCheck
    name: HealthCheck
    ```
    """

    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_healthcheck(self, context):
        return ok_response

    def register_endpoints(self):
        return [("^healthcheck$", self._handle_healthcheck)]
