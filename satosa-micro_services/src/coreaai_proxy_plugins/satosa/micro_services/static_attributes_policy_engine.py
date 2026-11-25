"""
SATOSA microservice that injects static attributes
based on local policy
"""

import logging

from satosa.micro_services.base import ResponseMicroService
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class StaticAttributesPolicyEngine(ResponseMicroService):
    """Inject configured static attribute values, subject to a per-attribute policy.

    Configuration is a mapping keyed by entity ID. The ``default`` (or ``""``)
    entry applies to every flow; an entry keyed by the IdP issuer entity ID, or by
    the requester (SP) entity ID, overrides it — the SP entry takes precedence over
    the IdP entry, which takes precedence over ``default``. Each entry holds:

    ``static_attributes`` (mapping)
        Attribute name to the value(s) to inject. A value may be a single string
        or a list of strings.
    ``policy`` (str, optional; default ``APPEND``)
        How configured values combine with any already present on the attribute:

        - ``APPEND``: add the configured values to the existing ones.
        - ``OVERWRITE``: replace any existing values with the configured ones.
        - ``DO_NOT_CHANGE_IF_EXISTS``: keep existing values; set the attribute
          only when it is absent.

    The request passes through unchanged when no matching configuration is found.
    """
    def __init__(self, config, internal_attributes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    def _parse_config(self, config, context, data):
        _config = config

        try:
            if 'default' in _config and "" in _config:
                msg = """Use either 'default' or "" in config but not both"""
                raise KeyError(msg)

            if "" in _config:
                _config['default'] = _config.pop("")

            if 'default' not in _config:
                msg = "No default configuration is present"
                raise KeyError(msg)

        except KeyError:
            return super().process(context, data)

        config = _config['default']

        try:
            spEntityID = context.state.state_dict['SATOSA_BASE']['requester']
        except KeyError:
            return super().process(context, data)

        # Find the entityID for the IdP that issued the assertion
        try:
            idpEntityID = data.to_dict()['auth_info']['issuer']
        except KeyError:
            return super().process(context, data)

        if idpEntityID in self.config:
            config = self.config[idpEntityID]

        # Examine our configuration to determine if there is a per-SP
        # configuration. An SP configuration overrides an IdP configuration
        # when there is a conflict.
        if spEntityID in self.config:
            config = self.config[spEntityID]

        return config

    @logging_wrapper(logger)
    def process(self, context, data):
        config = self._parse_config(self.config, context, data)
        try:
            if config == [] or config == "" or config == None:
                msg = "Empty configuration"
                raise KeyError(msg)
        except KeyError:
            return super().process(context, data)

        try:
            for attr in config["static_attributes"]:
                # For backwards compatibility: If policy set, then revert to
                # previous behaviour
                if 'policy' not in config:
                    config['policy'] = 'APPEND'

                # If an attribute is already set, the default behaviour is to
                # APPEND values. If the policy is set to OVERWRITE, then
                # attribute values will be replaced. If the policy is set to
                # DO_NOT_CHANGE_IF_EXISTS, then keep the original values
                if config['policy'] == 'OVERWRITE':
                    data.attributes[attr] = []
                elif attr not in data.attributes:
                    data.attributes[attr] = []
                elif config['policy'] == 'DO_NOT_CHANGE_IF_EXISTS':
                    continue

                if type(data.attributes[attr]) is str:
                    if type(config["static_attributes"][attr]) is str:
                        # data.attributes[attr] = [data.attributes[attr]]
                        data.attributes[attr] = config["static_attributes"][attr]
                    elif type(config["static_attributes"][attr]) is list:
                        data.attributes[attr] = config["static_attributes"][attr][0]
                elif type(data.attributes[attr]) is list:
                    if type(config["static_attributes"][attr]) is str:
                        data.attributes[attr].append(config["static_attributes"][attr])
                    elif type(config["static_attributes"][attr]) is list:
                        data.attributes[attr].extend(config["static_attributes"][attr])

        except Exception:
            return super().process(context, data)

        return super().process(context, data)
