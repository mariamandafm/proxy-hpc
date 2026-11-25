from collections.abc import Callable
from functools import wraps
from typing import TypeVar
from typing_extensions import ParamSpec, Concatenate



class Error(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.error_context = message


P = ParamSpec("P")
T = TypeVar("T")


def error_handler(handler: Callable[Concatenate[Exception, P], T]) -> Callable[P, T]:
    """
    Decorator for plugin.process method to intercept and handle exceptions
    """

    # TODO: If this is only used to redirect to an error page, it might be better
    #       to extend TableConfig to include an optional error_url and use
    #       a decorator without need for a callback argument.
    def error_handler_decorator(fn: Callable[P, T]) -> Callable[P, T]:
        @wraps(fn)
        def with_error_handler(*args: P, **kwargs: P) -> T:
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                return handler(e, *args, **kwargs)

        return with_error_handler

    return error_handler_decorator
