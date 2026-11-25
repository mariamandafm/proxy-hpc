from logging import LoggerAdapter

from satosa.response import Redirect
from satosa.exception import SATOSAError


class ExtraLogger(LoggerAdapter):
    def __init__(self, logger, extra={}):
        super().__init__(logger, extra)

    def bind(self, key, value):
        self.extra = {
            **self.extra,
            **{key: value}
        }

    def process(self, msg, kwargs):
        extra = " ".join(f"[{key}: {value}]" for key, value in self.extra.items())
        logline = "{extra} {msg}".format(extra=extra, msg=msg).lstrip()
        return logline, kwargs


def logging_wrapper(logger):

    def decorator(plugin_process):

        def next_log_wrapper(self, context, internal_data):
            plugin_name = self.__class__.__name__
            logger.debug(f"Returning: {internal_data}")
            logger.info(f"Finished processing {plugin_name}")
            return self.plugin_next(context, internal_data)

        def process_log_wrapper(self, context, internal_data):
            if not getattr(self, 'plugin_next', None):
                self.plugin_next = self.next
                delattr(self, 'next')
                setattr(self.__class__, 'next', next_log_wrapper)

            plugin_name = self.__class__.__name__
            logger.bind("session_id", context.state.session_id)
            logger.info(f"Started processing {plugin_name}")
            logger.debug(f"Received: {internal_data}")

            try:
                result = plugin_process(self, context, internal_data)
            except SATOSAError as e:
                logger.info(f"The flow is stopped because of a processing error: {e}")
                raise e
            except Exception as e:
                logger.error(f"Unhandled exception: {e}")
                raise e

            if type(result) is Redirect and not getattr(result, "_has_been_logged", None):
                result._has_been_logged = True
                logger.info(f"Redirecting from {plugin_name} to {result.message}")

            return result

        return process_log_wrapper

    return decorator
