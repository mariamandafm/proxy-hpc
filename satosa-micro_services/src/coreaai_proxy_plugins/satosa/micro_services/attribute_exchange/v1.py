"""Copy the value of one attribute to another attribute."""
import logging

from satosa.micro_services.base import ResponseMicroService

from coreaai_proxy_plugins.helpers.config import parse_config
from coreaai_proxy_plugins.helpers.logging import ExtraLogger
from coreaai_proxy_plugins.helpers.logging import logging_wrapper


logger = ExtraLogger(logging.getLogger(__name__))


class AttributeExchange(ResponseMicroService):
    """
    Copy the value of one attribute to another attribute.

    - the deepest value found, with priority to
      {issuer: requester: config} over {requester: issuer: config}
    - then, try the requester or issuer configs, with priority to
      {requester: config} over {issuer: config}
    - otherwise, fallback to an empty dict

    Example configuration:

    ```yaml
    module: coreaai_proxy_plugins.satosa.micro_services.attribute_exchange.AttributeExchange
    name: Copy the value of one attribute to another attribute.
    config:

      # - the empty string key is used to denote the default settings (legagy)
      # - the "default" string key is used to denote the default settings
      # - the non-empty (and not "default") string key is used to match an issuer id
      #   or a requester id
      #
      default:
        # If there is no match for the issuer id or the requester id then use this
        # configuration
        default:
          copy-this-attribute-value: to-this-attribute
        # If there is no match for the issuer id but there is a match for the
        # requester id then use this configuration
        https://sp.example.com:
          copy-this-attribute-value: to-this-attribute
        # If there is no match for the requester id but there is a match for the
        # issuer id then use this configuration
        https://idp.example.com
          copy-this-attribute-value: to-this-attribute
      https://idp.example.com:
        # If there is a match for the issuer id but there is not match for the requester
        # id then use this configuration
        default:
          copy-this-attribute-value: to-this-attribute
        # If there is a match for the issuer id and then the requester id then use
        # this configuration
        https://sp.example.com:
          copy-this-attribute-value: to-this-attribute
      https://sp.example.com:
        # If there is a match for the requester id but there is not match for the issuer
        # id then use this configuration
        default:
          copy-this-attribute-value: to-this-attribute
        # If there is a match for the requester id and then the issuer id then use
        # this configuration
        https://idp.example.com:
          copy-this-attribute-value: to-this-attribute
    ```
    """

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config

    @logging_wrapper(logger)
    def process(self, context, internal_data):
        requester = internal_data.requester
        issuer = internal_data.auth_info.issuer
        config = parse_config(self.config, issuer, requester)

        # select:
        # - the deepest value found, with priority to
        #   {issuer: requester: config} over {requester: issuer: config}
        # - then, try the requester or issuer configs, with priority to
        #   {requester: config} over {issuer: config}
        # - otherwise, fallback to an empty dict
        mappings = (
            config["by-iss-req"]
            or config["by-req-iss"]
            or config["by-requester"]
            or config["by-issuer"]
            or {}
        )

        logger.debug("Initialized with configuration: {}".format(mappings))

        for source, target in mappings.items():
            values_source = internal_data.attributes.get(source, [])
            if values_source:
                internal_data.attributes[target] = values_source

        return super().process(context, internal_data)
