"""Verify that a list of attributes is present in the AuthenticationResponse."""

from satosa.exception import SATOSAError


class CheckerError(SATOSAError):
    """Generic error."""


from .attributes import CheckerAttributes
from .aup import CheckerAUP
from .redirect import CheckerRedirect
from .shortlist import CheckerShortlist
from .loa import CheckerLoA
